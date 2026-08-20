import { z } from 'zod';
import type { GeneratedTripPlanResult } from '../dto/trip-plan-response.dto';

const boundedText = z.string().trim().min(1).max(1000);
const money = z.number().finite().nonnegative();

const daySessionSchema = z
  .object({
    time: boundedText,
    activity: boundedText,
    places: z.array(boundedText).max(20),
    estimatedCost: money,
    notes: z.string().trim().max(2000).optional(),
  })
  .strict();

const itineraryDaySchema = z
  .object({
    day: z.number().int().positive(),
    title: boundedText,
    morning: daySessionSchema,
    afternoon: daySessionSchema,
    evening: daySessionSchema,
  })
  .strict();

const budgetSchema = z
  .object({
    totalEstimated: money,
    costPerPerson: money,
    transportation: money,
    accommodation: money,
    foodAndDining: money,
    entertainmentAndTickets: money,
    contingency: money,
    currency: z.enum(['VNĐ', 'VND']),
  })
  .strict();

const generatedTripPlanSchema = z
  .object({
    destination: z
      .object({
        name: boundedText,
        tagline: boundedText,
        reason: boundedText,
        bestSeason: z.string().trim().max(500).optional(),
      })
      .strict(),
    budgetBreakdown: budgetSchema,
    itinerary: z.array(itineraryDaySchema).min(1).max(14),
    recommendedSpots: z
      .object({
        foodAndDrink: z
          .array(
            z
              .object({
                name: boundedText,
                type: boundedText,
                mustTry: boundedText,
                priceRange: boundedText,
                addressOrArea: boundedText,
              })
              .strict(),
          )
          .max(30),
        attractions: z
          .array(
            z
              .object({
                name: boundedText,
                type: boundedText,
                highlight: boundedText,
                ticketPrice: z.string().trim().max(500).optional(),
                bestTime: z.string().trim().max(500).optional(),
              })
              .strict(),
          )
          .max(30),
      })
      .strict(),
    travelTips: z.array(boundedText).max(30),
  })
  .strict();

export interface TripPlanValidationContext {
  days: number;
  numberOfPeople: number;
  maximumBudget: number;
}

export function validateGeneratedTripPlan(
  value: unknown,
  context: TripPlanValidationContext,
): GeneratedTripPlanResult {
  const result = generatedTripPlanSchema.parse(value);
  if (result.itinerary.length !== context.days) {
    throw new Error(
      `AI returned ${result.itinerary.length} days instead of ${context.days}`,
    );
  }
  if (result.itinerary.some((day, index) => day.day !== index + 1)) {
    throw new Error('Itinerary day numbers are not sequential');
  }

  const budget = result.budgetBreakdown;
  if (budget.totalEstimated > context.maximumBudget) {
    throw new Error('AI budget exceeds the requested maximum');
  }
  const componentTotal =
    budget.transportation +
    budget.accommodation +
    budget.foodAndDining +
    budget.entertainmentAndTickets +
    budget.contingency;
  const budgetTolerance = Math.max(10_000, budget.totalEstimated * 0.05);
  if (Math.abs(componentTotal - budget.totalEstimated) > budgetTolerance) {
    throw new Error('AI budget components do not match totalEstimated');
  }
  const expectedPerPerson = budget.totalEstimated / context.numberOfPeople;
  const perPersonTolerance = Math.max(5_000, expectedPerPerson * 0.05);
  if (Math.abs(budget.costPerPerson - expectedPerPerson) > perPersonTolerance) {
    throw new Error('AI costPerPerson does not match totalEstimated');
  }

  return {
    ...result,
    budgetBreakdown: { ...budget, currency: 'VNĐ' },
  };
}
