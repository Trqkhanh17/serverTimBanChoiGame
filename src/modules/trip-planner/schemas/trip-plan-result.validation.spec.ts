import type { GeneratedTripPlanResult } from '../dto/trip-plan-response.dto';
import { validateGeneratedTripPlan } from './trip-plan-result.validation';

describe('validateGeneratedTripPlan', () => {
  const result: GeneratedTripPlanResult = {
    destination: { name: 'Đà Lạt', tagline: 'Mát mẻ', reason: 'Phù hợp' },
    budgetBreakdown: {
      totalEstimated: 1_000_000,
      costPerPerson: 500_000,
      transportation: 200_000,
      accommodation: 250_000,
      foodAndDining: 250_000,
      entertainmentAndTickets: 200_000,
      contingency: 100_000,
      currency: 'VNĐ',
    },
    itinerary: [
      {
        day: 1,
        title: 'Ngày đầu',
        morning: {
          time: '08:00',
          activity: 'Tham quan',
          places: ['Hồ Xuân Hương'],
          estimatedCost: 50_000,
        },
        afternoon: {
          time: '13:00',
          activity: 'Khám phá',
          places: ['Quảng trường'],
          estimatedCost: 50_000,
        },
        evening: {
          time: '18:00',
          activity: 'Ăn tối',
          places: ['Chợ đêm'],
          estimatedCost: 100_000,
        },
      },
    ],
    recommendedSpots: { foodAndDrink: [], attractions: [] },
    travelTips: ['Kiểm tra thời tiết trước khi đi'],
  };

  const context = { days: 1, numberOfPeople: 2, maximumBudget: 1_200_000 };

  it('accepts a complete and internally consistent result', () => {
    expect(validateGeneratedTripPlan(result, context)).toMatchObject(result);
  });

  it('rejects negative costs and mismatched trip length', () => {
    expect(() =>
      validateGeneratedTripPlan(
        {
          ...result,
          budgetBreakdown: { ...result.budgetBreakdown, contingency: -1 },
        },
        context,
      ),
    ).toThrow();
    expect(() =>
      validateGeneratedTripPlan(result, { ...context, days: 2 }),
    ).toThrow(/instead of 2/);
  });

  it('rejects inconsistent budget components', () => {
    expect(() =>
      validateGeneratedTripPlan(
        {
          ...result,
          budgetBreakdown: {
            ...result.budgetBreakdown,
            transportation: 900_000,
          },
        },
        context,
      ),
    ).toThrow(/components/);
  });
});
