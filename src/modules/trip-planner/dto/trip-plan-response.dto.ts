export interface DestinationInfo {
  name: string;
  tagline: string;
  reason: string;
  bestSeason?: string;
}

export interface BudgetBreakdown {
  totalEstimated: number;
  costPerPerson: number;
  transportation: number;
  accommodation: number;
  foodAndDining: number;
  entertainmentAndTickets: number;
  contingency: number;
  currency: string;
}

export interface DaySession {
  time: string;
  activity: string;
  places: string[];
  estimatedCost: number;
  notes?: string;
}

export interface ItineraryDay {
  day: number;
  title: string;
  morning: DaySession;
  afternoon: DaySession;
  evening: DaySession;
}

export interface FoodSpot {
  name: string;
  type: string;
  mustTry: string;
  priceRange: string;
  addressOrArea: string;
}

export interface AttractionSpot {
  name: string;
  type: string;
  highlight: string;
  ticketPrice?: string;
  bestTime?: string;
}

export interface RecommendedSpots {
  foodAndDrink: FoodSpot[];
  attractions: AttractionSpot[];
}

export interface GeneratedTripPlanResult {
  destination: DestinationInfo;
  budgetBreakdown: BudgetBreakdown;
  itinerary: ItineraryDay[];
  recommendedSpots: RecommendedSpots;
  travelTips: string[];
}
