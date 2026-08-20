import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { TripPlannerService } from './trip-planner.service';
import { CreateTripPlanDto } from './dto/create-trip-plan.dto';
import { JwtAccessGuard } from '@/auth/passport/guards/jwt-access.guard';
import type { RequestWithUser } from '@/common/types/auth.types';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import type { Request } from 'express';

@Controller('trip-planner')
export class TripPlannerController {
  constructor(
    private readonly tripPlannerService: TripPlannerService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Helper method to extract optional user ID from Authorization header
   */
  private extractUserIdFromHeader(req: Request): string | undefined {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return undefined;
    }
    const token = authHeader.split(' ')[1];
    const jwtSecret = this.configService.get<string>('JWT_ACCESS_SECRET');
    if (!jwtSecret) return undefined;

    try {
      const decoded = jwt.verify(token, jwtSecret) as { sub?: string };
      return decoded.sub;
    } catch {
      return undefined;
    }
  }

  /**
   * Sinh kế hoạch du lịch bằng AI và lưu vào Database
   * Có thể gọi bởi khách vãng lai hoặc user đã đăng nhập
   */
  @Post('generate')
  async generateTripPlan(
    @Body() createTripPlanDto: CreateTripPlanDto,
    @Req() req: Request,
  ) {
    const userId = this.extractUserIdFromHeader(req);
    const plan = await this.tripPlannerService.generatePlan(
      createTripPlanDto,
      userId,
    );
    return {
      message: 'Tạo kế hoạch du lịch thành công!',
      data: plan,
    };
  }

  /**
   * Lấy danh sách lịch sử các chuyến đi của user đang đăng nhập
   */
  @UseGuards(JwtAccessGuard)
  @Get('my-trips')
  async getMyTrips(@Req() req: RequestWithUser) {
    const userId = req.user._id;
    const trips = await this.tripPlannerService.getUserPlans(userId);
    return {
      total: trips.length,
      data: trips,
    };
  }

  /**
   * Xem chi tiết kế hoạch du lịch theo ID
   */
  @Get(':id')
  async getTripPlanById(@Param('id') id: string, @Req() req: Request) {
    const userId = this.extractUserIdFromHeader(req);
    const plan = await this.tripPlannerService.getPlanById(id, userId);
    return {
      data: plan,
    };
  }

  /**
   * Bật / tắt chế độ chia sẻ công khai cho bạn bè
   */
  @UseGuards(JwtAccessGuard)
  @Patch(':id/share')
  async toggleShareTrip(@Param('id') id: string, @Req() req: RequestWithUser) {
    const userId = req.user._id;
    const updatedPlan = await this.tripPlannerService.toggleShare(id, userId);
    return {
      message: updatedPlan.isPublic
        ? 'Đã bật chế độ chia sẻ công khai'
        : 'Đã chuyển về chế độ riêng tư',
      isPublic: updatedPlan.isPublic,
      data: updatedPlan,
    };
  }

  /**
   * Xóa kế hoạch du lịch
   */
  @UseGuards(JwtAccessGuard)
  @Delete(':id')
  async deleteTripPlan(@Param('id') id: string, @Req() req: RequestWithUser) {
    const userId = req.user._id;
    return this.tripPlannerService.deletePlan(id, userId);
  }
}
