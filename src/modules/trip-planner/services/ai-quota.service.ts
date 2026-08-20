import { createHmac } from 'crypto';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AiUsage, type AiUsageDocument } from '../schemas/ai-usage.schema';

export interface AiQuotaStatus {
  limit: number;
  used: number;
  remaining: number;
  resetsAt: string;
}

@Injectable()
export class AiQuotaService {
  constructor(
    @InjectModel(AiUsage.name)
    private readonly usageModel: Model<AiUsageDocument>,
    private readonly configService: ConfigService,
  ) {}

  async consume(userId: string | undefined, requestIp: string): Promise<void> {
    const { identityHash, day, limit, expiresAt } = this.buildBucket(
      userId,
      requestIp,
    );
    try {
      const result = await this.usageModel
        .findOneAndUpdate(
          { identityHash, day, count: { $lt: limit } },
          {
            $inc: { count: 1 },
            $setOnInsert: { identityHash, day, expiresAt },
          },
          { new: true, upsert: true },
        )
        .exec();
      if (!result) throw this.quotaExceeded(limit);
    } catch (error: unknown) {
      if (error instanceof HttpException) throw error;
      if (isDuplicateKeyError(error)) {
        throw this.quotaExceeded(limit);
      }
      throw error;
    }
  }

  async getStatus(
    userId: string | undefined,
    requestIp: string,
  ): Promise<AiQuotaStatus> {
    const { identityHash, day, limit, resetsAt } = this.buildBucket(
      userId,
      requestIp,
    );
    const usage = await this.usageModel
      .findOne({ identityHash, day })
      .select('count')
      .lean()
      .exec();
    const used = Math.min(usage?.count ?? 0, limit);
    return {
      limit,
      used,
      remaining: Math.max(0, limit - used),
      resetsAt: resetsAt.toISOString(),
    };
  }

  private buildBucket(userId: string | undefined, requestIp: string) {
    const now = new Date();
    const day = now.toISOString().slice(0, 10);
    const resetsAt = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1),
    );
    const expiresAt = new Date(resetsAt.getTime() + 2 * 24 * 60 * 60 * 1000);
    const limit = Number(
      this.configService.get<string>(
        userId ? 'AI_DAILY_USER_LIMIT' : 'AI_DAILY_GUEST_LIMIT',
      ) ?? (userId ? 20 : 5),
    );
    const identity = userId ? `user:${userId}` : `guest:${requestIp}`;
    const salt =
      this.configService.get<string>('AI_QUOTA_SALT') ??
      this.configService.get<string>('JWT_ACCESS_SECRET') ??
      'development-only-quota-salt';
    const identityHash = createHmac('sha256', salt)
      .update(identity)
      .digest('hex');
    return { identityHash, day, limit, resetsAt, expiresAt };
  }

  private limitMessage(limit: number): string {
    return `Đã đạt giới hạn ${limit} lượt tạo lịch trình hôm nay.`;
  }

  private quotaExceeded(limit: number): HttpException {
    return new HttpException(
      this.limitMessage(limit),
      HttpStatus.TOO_MANY_REQUESTS,
    );
  }
}

function isDuplicateKeyError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 11_000
  );
}
