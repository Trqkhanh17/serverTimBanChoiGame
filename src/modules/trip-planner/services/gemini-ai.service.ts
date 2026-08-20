import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CreateTripPlanDto } from '../dto/create-trip-plan.dto';
import { GeneratedTripPlanResult } from '../dto/trip-plan-response.dto';
import {
  buildTripPlanResponseSchema,
  GenAiSchemaTypes,
} from '../schemas/trip-plan-response.schema';
import { buildTripPlanPrompt } from './trip-plan-prompt.builder';
import { validateGeneratedTripPlan } from '../schemas/trip-plan-result.validation';

interface GenAIClient {
  models: {
    generateContent(input: unknown): Promise<{ text?: string }>;
  };
}

interface GenAIModule {
  GoogleGenAI: new (options: { apiKey: string }) => GenAIClient;
  Type: GenAiSchemaTypes;
}

// The package exposes CommonJS at runtime while its declarations are ESM.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { GoogleGenAI, Type } = require('@google/genai') as GenAIModule;

@Injectable()
export class GeminiAiService {
  private readonly logger = new Logger(GeminiAiService.name);
  private readonly modelName: string;
  private ai: GenAIClient | null = null;

  constructor(private readonly configService: ConfigService) {
    this.modelName =
      this.configService.get<string>('GEMINI_MODEL') ?? 'gemini-3.5-flash-lite';

    const apiKey = this.configService.get<string>('GEMINI_API_KEY');
    if (apiKey) {
      this.ai = new GoogleGenAI({ apiKey });
      this.logger.log(`Gemini initialized with model: ${this.modelName}`);
    } else {
      this.logger.warn(
        'GEMINI_API_KEY is not configured; AI generation is disabled.',
      );
    }
  }

  async generateTripPlan(
    dto: CreateTripPlanDto,
  ): Promise<GeneratedTripPlanResult> {
    const { systemInstruction, userPrompt, totalBudget } =
      buildTripPlanPrompt(dto);

    try {
      this.logger.log(
        `Generating a trip plan for: ${dto.destinationPreference ?? 'automatic destination'}`,
      );
      const response = await this.withTimeout(
        this.getClient().models.generateContent({
          model: this.modelName,
          contents: userPrompt,
          config: {
            systemInstruction,
            responseMimeType: 'application/json',
            responseSchema: buildTripPlanResponseSchema(Type),
          },
        }),
      );

      return validateGeneratedTripPlan(this.parseResponse(response.text), {
        days: dto.days,
        numberOfPeople: dto.numberOfPeople,
        maximumBudget: totalBudget,
      });
    } catch (error: unknown) {
      this.logger.error('Gemini trip plan generation failed', error);
      if (error instanceof InternalServerErrorException) throw error;

      const message = error instanceof Error ? error.message : String(error);
      throw new InternalServerErrorException(
        `Lỗi khi tạo kế hoạch du lịch bằng AI: ${message}`,
      );
    }
  }

  private getClient(): GenAIClient {
    if (this.ai) return this.ai;

    const apiKey = this.configService.get<string>('GEMINI_API_KEY');
    if (!apiKey) {
      throw new InternalServerErrorException(
        'GEMINI_API_KEY chưa được cấu hình.',
      );
    }
    this.ai = new GoogleGenAI({ apiKey });
    return this.ai;
  }

  private parseResponse(responseText?: string): unknown {
    if (!responseText) {
      throw new InternalServerErrorException('AI không trả về dữ liệu hợp lệ.');
    }

    try {
      return JSON.parse(responseText) as unknown;
    } catch {
      throw new InternalServerErrorException('AI trả về JSON không hợp lệ.');
    }
  }

  private async withTimeout<T>(operation: Promise<T>): Promise<T> {
    const timeoutMs = Number(
      this.configService.get<string>('EXTERNAL_REQUEST_TIMEOUT_MS') ?? 25_000,
    );
    let timeout: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(
            () => reject(new Error(`Gemini timed out after ${timeoutMs}ms`)),
            timeoutMs,
          );
        }),
      ]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }
}
