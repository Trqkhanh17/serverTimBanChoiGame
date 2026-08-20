export interface GenAiSchemaTypes {
  OBJECT: string;
  STRING: string;
  NUMBER: string;
  INTEGER: string;
  ARRAY: string;
}

export function buildTripPlanResponseSchema(type: GenAiSchemaTypes) {
  const stringField = (description: string) => ({
    type: type.STRING,
    description,
  });
  const numberField = (description: string) => ({
    type: type.NUMBER,
    description,
  });
  const stringArray = (description: string) => ({
    type: type.ARRAY,
    description,
    items: { type: type.STRING },
  });
  const daySession = (period: string, timeExample: string) => ({
    type: type.OBJECT,
    properties: {
      time: stringField(`Khung giờ, ví dụ: ${timeExample}`),
      activity: stringField(`Mô tả hoạt động ${period}`),
      places: stringArray(`Danh sách các điểm đến ${period}`),
      estimatedCost: numberField(`Chi phí ước tính ${period} (VNĐ)`),
      notes: stringField(`Lưu ý ${period}`),
    },
    required: ['time', 'activity', 'places', 'estimatedCost'],
  });

  return {
    type: type.OBJECT,
    properties: {
      destination: {
        type: type.OBJECT,
        properties: {
          name: stringField('Tên địa điểm hoặc thành phố du lịch'),
          tagline: stringField('Khẩu hiệu hoặc mô tả ngắn gọn chuyến đi'),
          reason: stringField(
            'Lý do địa điểm phù hợp nhất với ngân sách và yêu cầu',
          ),
          bestSeason: stringField('Thời điểm lý tưởng nhất trong năm để đi'),
        },
        required: ['name', 'tagline', 'reason'],
      },
      budgetBreakdown: {
        type: type.OBJECT,
        properties: {
          totalEstimated: numberField('Tổng chi phí ước tính (VNĐ)'),
          costPerPerson: numberField('Chi phí ước tính trên đầu người (VNĐ)'),
          transportation: numberField('Chi phí di chuyển (VNĐ)'),
          accommodation: numberField('Chi phí khách sạn hoặc nơi ở (VNĐ)'),
          foodAndDining: numberField('Chi phí ăn uống (VNĐ)'),
          entertainmentAndTickets: numberField(
            'Chi phí vé tham quan và vui chơi (VNĐ)',
          ),
          contingency: numberField('Khoản dự phòng phát sinh (VNĐ)'),
          currency: stringField('Đơn vị tiền tệ (VNĐ)'),
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
        type: type.ARRAY,
        description: 'Lịch trình chi tiết theo từng ngày',
        items: {
          type: type.OBJECT,
          properties: {
            day: {
              type: type.INTEGER,
              description: 'Ngày thứ mấy trong chuyến đi',
            },
            title: stringField('Chủ đề của ngày'),
            morning: daySession('buổi sáng', '07:30 - 11:30'),
            afternoon: daySession('buổi chiều', '12:00 - 17:30'),
            evening: daySession('buổi tối', '18:00 - 22:30'),
          },
          required: ['day', 'title', 'morning', 'afternoon', 'evening'],
        },
      },
      recommendedSpots: {
        type: type.OBJECT,
        properties: {
          foodAndDrink: {
            type: type.ARRAY,
            description: 'Danh sách quán ăn đặc sản và cafe nên thử',
            items: {
              type: type.OBJECT,
              properties: {
                name: stringField('Tên quán ăn hoặc nhà hàng'),
                type: stringField('Loại hình như ăn sáng, hải sản, cafe'),
                mustTry: stringField('Món nhất định phải thử'),
                priceRange: stringField('Mức giá tham khảo'),
                addressOrArea: stringField('Địa chỉ hoặc khu vực'),
              },
              required: [
                'name',
                'type',
                'mustTry',
                'priceRange',
                'addressOrArea',
              ],
            },
          },
          attractions: {
            type: type.ARRAY,
            description: 'Danh sách điểm tham quan, check-in và vui chơi',
            items: {
              type: type.OBJECT,
              properties: {
                name: stringField('Tên địa điểm'),
                type: stringField('Loại hình như biển, di tích, check-in'),
                highlight: stringField('Điểm đặc sắc nhất'),
                ticketPrice: stringField('Giá vé tham khảo'),
                bestTime: stringField('Thời điểm đẹp nhất trong ngày'),
              },
              required: ['name', 'type', 'highlight'],
            },
          },
        },
        required: ['foodAndDrink', 'attractions'],
      },
      travelTips: stringArray(
        'Mẹo du lịch, lưu ý thời tiết, đặt phòng và phương tiện',
      ),
    },
    required: [
      'destination',
      'budgetBreakdown',
      'itinerary',
      'recommendedSpots',
      'travelTips',
    ],
  };
}
