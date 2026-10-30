package handler

import "github.com/AUPLA-Labs/loupe/internal/underattack"

// UnderAttack is the dashboard's under-attack switch. Its floor is applied
// at dispatch and its clearance cut-off in checkClearance.
func (h *Handler) UnderAttack() *underattack.Switch { return h.underAttack }
