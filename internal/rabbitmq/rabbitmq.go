package rabbitmq

import (
	"fmt"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	ExchangeName        = "smart_notes.direct"
	WaitingQueueName    = "notes.wait"
	ProcessingQueueName = "notes.process"
	RoutingKeyWait      = "wait"
	RoutingKeyProcess   = "process"
	ReconnectDelay      = 5 * time.Second
)

type RabbitMQClient struct {
	Conn    *amqp.Connection
	Channel *amqp.Channel
	URL     string
}

var Client *RabbitMQClient

// SetupRabbitMQ initializes the connection and declares the topology
func SetupRabbitMQ(url string) error {
	Client = &RabbitMQClient{
		URL: url,
	}
	return Client.connect()
}

func (c *RabbitMQClient) connect() error {
	var err error

	log.Printf("Attempting to connect to RabbitMQ...")
	c.Conn, err = amqp.Dial(c.URL)
	if err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	c.Channel, err = c.Conn.Channel()
	if err != nil {
		c.Conn.Close()
		return fmt.Errorf("failed to open a channel: %w", err)
	}

	// Declare Topology
	if err := c.declareTopology(); err != nil {
		c.Channel.Close()
		c.Conn.Close()
		return err
	}

	// Watch for errors in background
	go c.watchConnection()

	log.Println("RabbitMQ connected successfully")
	return nil
}

func (c *RabbitMQClient) declareTopology() error {
	// 2. Declare Exchange
	err := c.Channel.ExchangeDeclare(
		ExchangeName, // name
		"direct",     // type
		true,         // durable
		false,        // auto-deleted
		false,        // internal
		false,        // no-wait
		nil,          // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare exchange: %w", err)
	}

	// 3. Declare Processing Queue (Consumer listens here)
	_, err = c.Channel.QueueDeclare(
		ProcessingQueueName, // name
		true,                // durable
		false,               // delete when unused
		false,               // exclusive
		false,               // no-wait
		nil,                 // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare processing queue: %w", err)
	}

	// Bind Processing Queue to Exchange
	err = c.Channel.QueueBind(
		ProcessingQueueName, // queue name
		RoutingKeyProcess,   // routing key
		ExchangeName,        // exchange
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to bind processing queue: %w", err)
	}

	// 4. Declare Waiting Queue (TTL + DLX)
	args := amqp.Table{
		"x-dead-letter-exchange":    ExchangeName,
		"x-dead-letter-routing-key": RoutingKeyProcess,
	}
	_, err = c.Channel.QueueDeclare(
		WaitingQueueName, // name
		true,             // durable
		false,            // delete when unused
		false,            // exclusive
		false,            // no-wait
		args,             // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare waiting queue: %w", err)
	}

	// Bind Waiting Queue to Exchange
	err = c.Channel.QueueBind(
		WaitingQueueName, // queue name
		RoutingKeyWait,   // routing key
		ExchangeName,     // exchange
		false,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to bind waiting queue: %w", err)
	}

	return nil
}

func (c *RabbitMQClient) watchConnection() {
	// Clean way to handle different notify channels
	notifyClose := c.Conn.NotifyClose(make(chan *amqp.Error))

	select {
	case err := <-notifyClose:
		if err != nil {
			log.Printf("RabbitMQ connection closed: %v. Reconnecting...", err)
			c.reconnect()
		}
	}
}

func (c *RabbitMQClient) reconnect() {
	for {
		time.Sleep(ReconnectDelay)
		if err := c.connect(); err == nil {
			log.Println("RabbitMQ reconnected")
			return
		} else {
			log.Printf("Failed to reconnect to RabbitMQ: %v. Retrying in %v...", err, ReconnectDelay)
		}
	}
}

// Close closes the connection and channel
func Close() {
	if Client != nil {
		if Client.Channel != nil {
			Client.Channel.Close()
		}
		if Client.Conn != nil {
			Client.Conn.Close()
		}
	}
}

// PublishScheduleNote publishes a note ID to the waiting queue with a specific expiration delay
func PublishScheduleNote(noteID string, delay time.Duration) error {
	if Client == nil || Client.Channel == nil || Client.Channel.IsClosed() {
		return fmt.Errorf("RabbitMQ client not (yet) connected")
	}

	// Convert duration to milliseconds string for expiration
	expirationMs := fmt.Sprintf("%d", delay.Milliseconds())

	err := Client.Channel.Publish(
		ExchangeName,   // exchange
		RoutingKeyWait, // routing key (send to waiting queue)
		false,          // mandatory
		false,          // immediate
		amqp.Publishing{
			ContentType:  "text/plain",
			Body:         []byte(noteID),
			Expiration:   expirationMs, // TTL in milliseconds
			DeliveryMode: amqp.Persistent,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	return nil
}
