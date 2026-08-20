import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CreateTripPlanDto, BudgetType } from '../dto/create-trip-plan.dto';
import { GeneratedTripPlanResult } from '../dto/trip-plan-response.dto';

// Dynamic require for @google/genai in CommonJS environment
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { GoogleGenAI, Type } = require('@google/genai');

@Injectable()
export class GeminiAiService {
  private readonly logger = new Logger(GeminiAiService.name);
  private ai: any = null;
  private readonly modelName: string;

  constructor(private readonly configService: ConfigService) {
    const apiKey = this.configService.get<string>('GEMINI_API_KEY');
    this.modelName =
      this.configService.get<string>('GEMINI_MODEL') || 'gemini-2.0-flash';

    if (apiKey) {
      this.ai = new GoogleGenAI({ apiKey });
      this.logger.log(`Gemini AI Service initialized with model: ${this.modelName}`);
    } else {
      this.logger.warn(
        'GEMINI_API_KEY is not set in environment variables. AI generation will be disabled until key is added.',
      );
    }
  }

  private getGenAI(): any {
    if (!this.ai) {
      const apiKey = this.configService.get<string>('GEMINI_API_KEY');
      if (!apiKey) {
        throw new InternalServerErrorException(
          'GEMINI_API_KEY chưa được cấu hình trong file .env. Vui lòng thêm GEMINI_API_KEY để sử dụng tính năng AI này.',
        );
      }
      this.ai = new GoogleGenAI({ apiKey });
    }
    return this.ai;
  }

  async generateTripPlan(
    dto: CreateTripPlanDto,
  ): Promise<GeneratedTripPlanResult> {
    const aiClient = this.getGenAI();

    const nights = dto.nights !== undefined ? dto.nights : Math.max(0, dto.days - 1);
    const totalBudget =
      dto.budgetType === BudgetType.PER_PERSON
        ? dto.budget * dto.numberOfPeople
        : dto.budget;

    const stylesText = dto.tripStyles?.length
      ? dto.tripStyles.join(', ')
      : 'Nghỉ dưỡng, Ẩm thực';

    const systemInstruction = `
Bạn là chuyên gia tư vấn du lịch và ẩm thực hàng đầu tại Việt Nam (và quốc tế nếu được yêu cầu).
Nhiệm vụ của bạn là phân tích yêu cầu của người dùng để thiết kế một kế hoạch du lịch - ăn chơi chi tiết, thực tế, tối ưu hóa ngân sách và mang lại trải nghiệm tuyệt vời nhất.

Quy tắc tính toán và phân bổ chi phí:
1. Ngân sách phải được phân bổ thực tế theo thời giá hiện tại (VNĐ):
   - Phương tiện di chuyển (vé xe/tàu/máy bay, xăng xe, thuê xe máy/ô tô, taxi/grab).
   - Lưu trú (khách sạn/homestay/resort phù hợp với ngân sách).
   - Ăn uống (bữa sáng, trưa, tối, ăn vặt, cafe).
   - Vé tham quan, vui chơi giải trí.
   - Quỹ dự phòng (khoảng 5-10% tổng ngân sách).
2. Tổng chi phí ước tính (totalEstimated) KHÔNG ĐƯỢC vượt quá tổng ngân sách người dùng cho phép (${totalBudget.toLocaleString('vi-VN')} VNĐ).
3. Lịch trình phải logic về mặt địa lý, khoảng cách giữa các điểm tham quan/quán ăn trong cùng một buổi phải thuận tiện di chuyển.
4. Gợi ý các quán ăn nổi tiếng, chuẩn vị địa phương, có giá cả minh bạch và địa chỉ cụ thể.
5. Luôn trả về dữ liệu tuân thủ 100% định dạng JSON Schema được chỉ định.
`;

    const userPrompt = `
Hãy lập kế hoạch du lịch chi tiết với các tiêu chí sau:
- Điểm xuất phát: ${dto.originLocation}
- Điểm đến mong muốn: ${dto.destinationPreference || 'Hãy tự động chọn điểm đến tối ưu nhất phù hợp với ngân sách và sở thích'}
- Tổng ngân sách: ${totalBudget.toLocaleString('vi-VN')} VNĐ cho cả đoàn (${(totalBudget / dto.numberOfPeople).toLocaleString('vi-VN')} VNĐ / người)
- Số lượng người: ${dto.numberOfPeople} người
- Thời gian: ${dto.days} ngày ${nights} đêm
- Phong cách du lịch/ăn chơi: ${stylesText}
- Phương tiện ưu tiên: ${dto.transportationPreference || 'Tự do/Phù hợp nhất'}
- Yêu cầu đặc biệt: ${dto.specialNotes || 'Không có'}
`;

    const tripPlanResponseSchema = {
      type: Type.OBJECT,
      properties: {
        destination: {
          type: Type.OBJECT,
          properties: {
            name: {
              type: Type.STRING,
              description: 'Tên địa điểm / thành phố du lịch',
            },
            tagline: {
              type: Type.STRING,
              description: 'Khẩu hiệu hoặc mô tả ngắn gọn chuyến đi',
            },
            reason: {
              type: Type.STRING,
              description: 'Lý do địa điểm này phù hợp nhất với ngân sách và yêu cầu',
            },
            bestSeason: {
              type: Type.STRING,
              description: 'Thời điểm lý tưởng nhất trong năm để đi',
            },
          },
          required: ['name', 'tagline', 'reason'],
        },
        budgetBreakdown: {
          type: Type.OBJECT,
          properties: {
            totalEstimated: {
              type: Type.NUMBER,
              description: 'Tổng chi phí ước tính (VNĐ)',
            },
            costPerPerson: {
              type: Type.NUMBER,
              description: 'Chi phí ước tính trên đầu người (VNĐ)',
            },
            transportation: {
              type: Type.NUMBER,
              description: 'Chi phí di chuyển (VNĐ)',
            },
            accommodation: {
              type: Type.NUMBER,
              description: 'Chi phí khách sạn / nơi ở (VNĐ)',
            },
            foodAndDining: {
              type: Type.NUMBER,
              description: 'Chi phí ăn uống (VNĐ)',
            },
            entertainmentAndTickets: {
              type: Type.NUMBER,
              description: 'Chi phí vé tham quan & vui chơi (VNĐ)',
            },
            contingency: {
              type: Type.NUMBER,
              description: 'Khoản dự phòng phát sinh (VNĐ)',
            },
            currency: {
              type: Type.STRING,
              description: 'Đơn vị tiền tệ (VNĐ)',
            },
          },
          required: [
            'totalEstimated',
            'costPerPerson',
            'transportation',
            'accommodation',
            'foodAndDining',
            'entertainmentAndTickets',
            'contingency',
            'currency',
          ],
        },
        itinerary: {
          type: Type.ARRAY,
          description: 'Lịch trình chi tiết theo từng ngày',
          items: {
            type: Type.OBJECT,
            properties: {
              day: { type: Type.INTEGER, description: 'Ngày thứ mấy (1, 2, 3...)' },
              title: { type: Type.STRING, description: 'Chủ đề của ngày' },
              morning: {
                type: Type.OBJECT,
                properties: {
                  time: { type: Type.STRING, description: 'Khung giờ, vd: 07:30 - 11:30' },
                  activity: { type: Type.STRING, description: 'Mô tả hoạt động chi tiết' },
                  places: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING },
                    description: 'Danh sách các điểm đến buổi sáng',
                  },
                  estimatedCost: {
                    type: Type.NUMBER,
                    description: 'Chi phí ước tính buổi sáng (VNĐ)',
                  },
                  notes: { type: Type.STRING, description: 'Lưu ý buổi sáng' },
                },
                required: ['time', 'activity', 'places', 'estimatedCost'],
              },
              afternoon: {
                type: Type.OBJECT,
                properties: {
                  time: { type: Type.STRING, description: 'Khung giờ, vd: 12:00 - 17:30' },
                  activity: { type: Type.STRING, description: 'Mô tả hoạt động buổi chiều' },
                  places: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING },
                    description: 'Danh sách các điểm đến buổi chiều',
                  },
                  estimatedCost: {
                    type: Type.NUMBER,
                    description: 'Chi phí ước tính buổi chiều (VNĐ)',
                  },
                  notes: { type: Type.STRING, description: 'Lưu ý buổi chiều' },
                },
                required: ['time', 'activity', 'places', 'estimatedCost'],
              },
              evening: {
                type: Type.OBJECT,
                properties: {
                  time: { type: Type.STRING, description: 'Khung giờ, vd: 18:00 - 22:30' },
                  activity: { type: Type.STRING, description: 'Mô tả hoạt động buổi tối/đêm' },
                  places: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING },
                    description: 'Danh sách các điểm đến buổi tối',
                  },
                  estimatedCost: {
                    type: Type.NUMBER,
                    description: 'Chi phí ước tính buổi tối (VNĐ)',
                  },
                  notes: { type: Type.STRING, description: 'Lưu ý buổi tối' },
                },
                required: ['time', 'activity', 'places', 'estimatedCost'],
              },
            },
            required: ['day', 'title', 'morning', 'afternoon', 'evening'],
          },
        },
        recommendedSpots: {
          type: Type.OBJECT,
          properties: {
            foodAndDrink: {
              type: Type.ARRAY,
              description: 'Danh sách quán ăn đặc sản & cafe nên thử',
              items: {
                type: Type.OBJECT,
                properties: {
                  name: { type: Type.STRING, description: 'Tên quán ăn / nhà hàng' },
                  type: { type: Type.STRING, description: 'Loại hình (Ăn sáng, Hải sản, Cafe...)' },
                  mustTry: { type: Type.STRING, description: 'Món nhất định phải thử' },
                  priceRange: { type: Type.STRING, description: 'Mức giá tham khảo' },
                  addressOrArea: { type: Type.STRING, description: 'Địa chỉ hoặc khu vực' },
                },
                required: ['name', 'type', 'mustTry', 'priceRange', 'addressOrArea'],
              },
            },
            attractions: {
              type: Type.ARRAY,
              description: 'Danh sách điểm tham quan, check-in, vui chơi',
              items: {
                type: Type.OBJECT,
                properties: {
                  name: { type: Type.STRING, description: 'Tên địa điểm' },
                  type: { type: Type.STRING, description: 'Loại hình (Biển, Di tích, Check-in...)' },
                  highlight: { type: Type.STRING, description: 'Điểm đặc sắc nhất' },
                  ticketPrice: { type: Type.STRING, description: 'Giá vé tham khảo' },
                  bestTime: { type: Type.STRING, description: 'Thời điểm đẹp nhất trong ngày' },
                },
                required: ['name', 'type', 'highlight'],
              },
            },
          },
          required: ['foodAndDrink', 'attractions'],
        },
        travelTips: {
          type: Type.ARRAY,
          description: 'Mẹo du lịch hữu ích, lưu ý thời tiết, đặt phòng, phương tiện',
          items: { type: Type.STRING },
        },
      },
      required: [
        'destination',
        'budgetBreakdown',
        'itinerary',
        'recommendedSpots',
        'travelTips',
      ],
    };

    try {
      this.logger.log(`Calling Gemini API (${this.modelName}) for destination: ${dto.destinationPreference || 'Auto'}`);

      const response = await aiClient.models.generateContent({
        model: this.modelName,
        contents: userPrompt,
        config: {
          systemInstruction: systemInstruction,
          responseMimeType: 'application/json',
          responseSchema: tripPlanResponseSchema,
          temperature: 0.7,
        },
      });

      const responseText = response.text;
      if (!responseText) {
        throw new InternalServerErrorException('AI không trả về dữ liệu hợp lệ.');
      }

      const result = JSON.parse(responseText) as GeneratedTripPlanResult;
      return result;
    } catch (error: any) {
      this.logger.error('Error generating trip plan with Gemini AI', error);
      if (error instanceof InternalServerErrorException) {
        throw error;
      }
      throw new InternalServerErrorException(
        `Lỗi khi tạo kế hoạch du lịch bằng AI: ${error?.message || String(error)}`,
      );
    }
  }
}
