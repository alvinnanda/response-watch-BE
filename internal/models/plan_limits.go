package models

const (
	PlanFree       = "free"
	PlanBasic      = "basic"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

type PlanLimits struct {
	MonthlyRequests int // 0 = unlimited
	NotesPerRequest int // 0 = unlimited
	HistoryDays     int // 0 = unlimited
	VendorGroups    int // 0 = unlimited
	SecureDesc      bool
	Reminder        bool
}

func GetPlanLimits(plan string) PlanLimits {
	limits := map[string]PlanLimits{
		PlanFree: {
			MonthlyRequests: 10,
			NotesPerRequest: 3,
			HistoryDays:     30,
			VendorGroups:    1,
			SecureDesc:      false,
			Reminder:        false,
		},
		PlanBasic: {
			MonthlyRequests: 0, // unlimited
			NotesPerRequest: 10,
			HistoryDays:     90,
			VendorGroups:    3,
			SecureDesc:      false,
			Reminder:        false,
		},
		PlanPro: {
			MonthlyRequests: 0,
			NotesPerRequest: 0, // unlimited
			HistoryDays:     365,
			VendorGroups:    0, // unlimited
			SecureDesc:      true,
			Reminder:        true,
		},
		PlanEnterprise: {
			MonthlyRequests: 0,
			NotesPerRequest: 0,
			HistoryDays:     0, // unlimited
			VendorGroups:    0, // unlimited
			SecureDesc:      true,
			Reminder:        true,
		},
	}

	// Default to free if unknown plan
	if l, ok := limits[plan]; ok {
		return l
	}
	return limits[PlanFree]
}
