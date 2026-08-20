import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { TripPlan, TripPlanDocument } from './schemas/trip-plan.schema';
import { CreateTripPlanDto } from './dto/create-trip-plan.dto';
import { GeminiAiService } from './services/gemini-ai.service';

@Injectable()
export class TripPlannerService {
  constructor(
    @InjectModel(TripPlan.name)
    private readonly tripPlanModel: Model<TripPlanDocument>,
    private readonly geminiAiService: GeminiAiService,
  ) {}

  async generatePlan(
    dto: CreateTripPlanDto,
    userId?: string,
  ): Promise<TripPlanDocument> {
    const aiResult = await this.geminiAiService.generateTripPlan(dto);

    const newTripPlan = await this.tripPlanModel.create({
      userId: userId ? new Types.ObjectId(userId) : null,
      inputCriteria: dto,
      destination: aiResult.destination,
      budgetBreakdown: aiResult.budgetBreakdown,
      itinerary: aiResult.itinerary,
      recommendedSpots: aiResult.recommendedSpots,
      travelTips: aiResult.travelTips,
      isPublic: false,
    });

    return newTripPlan;
  }

  async getUserPlans(userId: string): Promise<TripPlanDocument[]> {
    return this.tripPlanModel
      .find({ userId: new Types.ObjectId(userId) })
      .sort({ createdAt: -1 })
      .exec();
  }

  async getPlanById(id: string, userId?: string): Promise<TripPlanDocument> {
    if (!Types.ObjectId.isValid(id)) {
      throw new NotFoundException('ID kế hoạch không hợp lệ.');
    }

    const plan = await this.tripPlanModel.findById(id).exec();
    if (!plan) {
      throw new NotFoundException('Không tìm thấy kế hoạch du lịch này.');
    }

    // If private and not owned by current user (and user is requested)
    if (!plan.isPublic && plan.userId) {
      if (!userId || plan.userId.toString() !== userId.toString()) {
        throw new ForbiddenException(
          'Bạn không có quyền truy cập kế hoạch du lịch riêng tư này.',
        );
      }
    }

    return plan;
  }

  async deletePlan(id: string, userId: string): Promise<{ message: string }> {
    if (!Types.ObjectId.isValid(id)) {
      throw new NotFoundException('ID kế hoạch không hợp lệ.');
    }

    const plan = await this.tripPlanModel.findById(id).exec();
    if (!plan) {
      throw new NotFoundException('Không tìm thấy kế hoạch du lịch để xóa.');
    }

    if (!plan.userId || plan.userId.toString() !== userId.toString()) {
      throw new ForbiddenException(
        'Bạn chỉ có thể xóa kế hoạch của chính mình.',
      );
    }

    await this.tripPlanModel.findByIdAndDelete(id).exec();
    return { message: 'Đã xóa kế hoạch du lịch thành công.' };
  }

  async toggleShare(id: string, userId: string): Promise<TripPlanDocument> {
    if (!Types.ObjectId.isValid(id)) {
      throw new NotFoundException('ID kế hoạch không hợp lệ.');
    }

    const plan = await this.tripPlanModel.findById(id).exec();
    if (!plan) {
      throw new NotFoundException('Không tìm thấy kế hoạch du lịch.');
    }

    if (!plan.userId || plan.userId.toString() !== userId.toString()) {
      throw new ForbiddenException(
        'Bạn chỉ có thể thay đổi trạng thái chia sẻ kế hoạch của chính mình.',
      );
    }

    plan.isPublic = !plan.isPublic;
    return plan.save();
  }
}
