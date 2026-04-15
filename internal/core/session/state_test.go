package session

import "testing"

func TestStateCheckAndReserveCostLocalRollbackAndConfirm(t *testing.T) {
	s := NewState(10)

	ok, err := s.CheckAndReserveCost(4, 10, 10)
	if err != nil || !ok {
		t.Fatalf("reserve cost: ok=%v err=%v", ok, err)
	}
	if got := s.CurrentCostUSD(); got != 4 {
		t.Fatalf("current cost = %v, want 4", got)
	}
	if err := s.RollbackReservedCost(4); err != nil {
		t.Fatalf("rollback reserved cost: %v", err)
	}
	if got := s.CurrentCostUSD(); got != 0 {
		t.Fatalf("current cost after rollback = %v, want 0", got)
	}

	ok, err = s.CheckAndReserveCost(6, 10, 10)
	if err != nil || !ok {
		t.Fatalf("second reserve cost: ok=%v err=%v", ok, err)
	}
	if err := s.ConfirmReservedCost(6); err != nil {
		t.Fatalf("confirm reserved cost: %v", err)
	}
	if got := s.CurrentCostUSD(); got != 6 {
		t.Fatalf("current cost after confirm = %v, want 6", got)
	}

	ok, err = s.CheckAndReserveCost(5, 10, 10)
	if err != nil {
		t.Fatalf("reserve over limit err = %v", err)
	}
	if ok {
		t.Fatalf("expected reserve over limit to be rejected")
	}
	if got := s.CurrentCostUSD(); got != 6 {
		t.Fatalf("current cost after rejected reserve = %v, want 6", got)
	}
}
