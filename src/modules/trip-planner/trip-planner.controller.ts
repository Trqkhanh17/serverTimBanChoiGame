import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { TripPlannerService } from './trip-planner.service';
import { CreateTripPlanDto } from './dto/create-trip-plan.dto';
import { JwtAccessGuard } from '@/auth/passport/guards/jwt-access.guard';
import type {
  OptionalRequestWithUser,
  RequestWithUser,
} from '@/common/types/auth.types';
import { TripPlanQueryDto } from './dto/trip-plan-query.dto';
import { OptionalJwtAccessGuard } from '@/auth/passport/guards/optional-jwt-access.guard';
import { minutes, Throttle } from '@nestjs/throttler';

@Controller('trip-planner')
export class TripPlannerController {
  constructor(private readonly tripPlannerService: TripPlannerService) {}

  /**
   * Sinh kế hoạch du lịch bằng AI và lưu vào Database
   * Có thể gọi bởi khách vãng lai hoặc user đã đăng nhập
   */
  @Post('generate')
  @UseGuards(OptionalJwtAccessGuard)
  @Throttle({
    default: { limit: 5, ttl: minutes(1), blockDuration: minutes(5) },
  })
  async generateTripPlan(
    @Body() createTripPlanDto: CreateTripPlanDto,
    @Req() req: OptionalRequestWithUser,
  ) {
    const userId = req.user?._id;
    const plan = await this.tripPlannerService.generatePlan(
      createTripPlanDto,
      userId,
      req.ip,
    );
    return {
      message: 'Tạo kế hoạch du lịch thành công!',
      data: plan.plan,
      guest_manage_token: plan.guestManageToken,
    };
  }

  @Get('quota')
  @UseGuards(OptionalJwtAccessGuard)
  getQuota(@Req() req: OptionalRequestWithUser) {
    return this.tripPlannerService.getQuotaStatus(
      req.user?._id,
      req.ip ?? 'unknown',
    );
  }

  /**
   * Lấy danh sách lịch sử các chuyến đi của user đang đăng nhập
   */
  @UseGuards(JwtAccessGuard)
  @Get('my-trips')
  async getMyTrips(
    @Req() req: RequestWithUser,
    @Query() query: TripPlanQueryDto,
  ) {
    const userId = req.user._id;
    return this.tripPlannerService.getUserPlans(
      userId,
      query.page,
      query.limit,
    );
  }

  /** Danh sách lịch trình được chia sẻ công khai */
  @Get('public')
  async getPublicTrips(@Query() query: TripPlanQueryDto) {
    return this.tripPlannerService.getPublicPlans(query.page, query.limit);
  }

  /**
   * Xem chi tiết kế hoạch du lịch theo ID
   */
  @Get(':id')
  @UseGuards(OptionalJwtAccessGuard)
  async getTripPlanById(
    @Param('id') id: string,
    @Req() req: OptionalRequestWithUser,
  ) {
    const userId = req.user?._id;
    const plan = await this.tripPlannerService.getPlanById(
      id,
      userId,
      req.header('x-guest-token'),
    );
    return {
      data: plan,
    };
  }

  @UseGuards(JwtAccessGuard)
  @Post(':id/claim')
  async claimGuestTrip(@Param('id') id: string, @Req() req: RequestWithUser) {
    const plan = await this.tripPlannerService.claimGuestPlan(
      id,
      req.user._id,
      req.header('x-guest-token'),
    );
    return { message: 'Đã lưu kế hoạch vào tài khoản.', data: plan };
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
  @UseGuards(OptionalJwtAccessGuard)
  @Delete(':id')
  async deleteTripPlan(
    @Param('id') id: string,
    @Req() req: OptionalRequestWithUser,
  ) {
    return this.tripPlannerService.deletePlan(
      id,
      req.user?._id,
      req.header('x-guest-token'),
    );
  }
}
