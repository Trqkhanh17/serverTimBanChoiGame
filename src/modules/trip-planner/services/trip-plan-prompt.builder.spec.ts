import { BudgetType } from '../dto/create-trip-plan.dto';
import { buildTripPlanPrompt } from './trip-plan-prompt.builder';

describe('buildTripPlanPrompt', () => {
  it('converts per-person budget into the maximum group budget', () => {
    const prompt = buildTripPlanPrompt({
      budget: 1_500_000,
      budgetType: BudgetType.PER_PERSON,
      numberOfPeople: 3,
      originLocation: 'TP.HCM',
      days: 2,
    });

    expect(prompt.totalBudget).toBe(4_500_000);
    expect(prompt.userPrompt).toContain('4.500.000 VNĐ cho cả đoàn');
    expect(prompt.userPrompt).toContain('2 ngày 1 đêm');
  });

  it('uses an explicitly supplied number of nights', () => {
    const prompt = buildTripPlanPrompt({
      budget: 3_000_000,
      budgetType: BudgetType.TOTAL,
      numberOfPeople: 2,
      originLocation: 'Hà Nội',
      days: 3,
      nights: 1,
    });

    expect(prompt.totalBudget).toBe(3_000_000);
    expect(prompt.userPrompt).toContain('3 ngày 1 đêm');
  });
});
