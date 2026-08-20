# Product Requirements Document (PRD)

## AI Travel & Outing Planner

| Thuộc tính    | Giá trị                                                |
| ------------- | ------------------------------------------------------ |
| Phiên bản     | 1.0                                                    |
| Trạng thái    | Baseline theo sản phẩm đã triển khai                   |
| Ngày cập nhật | 20/08/2026                                             |
| Phạm vi       | Backend API `ai-travel-planner-server`                 |
| Đối tượng đọc | Product Owner, Business Analyst, Developer, QA, DevOps |

## 1. Tóm tắt sản phẩm

AI Travel & Outing Planner là dịch vụ backend giúp người dùng tạo kế hoạch du lịch dựa trên ngân sách, số người, thời gian, điểm xuất phát, điểm đến mong muốn và phong cách trải nghiệm. Hệ thống sử dụng Google Gemini để tạo kết quả có cấu trúc, sau đó lưu kế hoạch vào MongoDB để người dùng xem lại, chia sẻ hoặc xóa.

Sản phẩm hỗ trợ hai cách sử dụng:

- Khách vãng lai có thể tạo kế hoạch không cần tài khoản. Kế hoạch mặc định riêng tư, có thời hạn và được quản lý bằng guest token chỉ trả một lần.
- Người dùng đã đăng nhập có thể tạo kế hoạch riêng tư, quản lý lịch sử và chủ động bật hoặc tắt chia sẻ công khai.

Ngoài chức năng lập kế hoạch, hệ thống cung cấp đầy đủ vòng đời tài khoản gồm đăng ký, xác minh email, đăng nhập, làm mới token, cập nhật hồ sơ, đổi mật khẩu, quên mật khẩu và đăng xuất.

## 2. Bối cảnh và vấn đề cần giải quyết

Người đi du lịch thường phải tự tổng hợp thông tin từ nhiều nguồn để trả lời các câu hỏi:

- Với ngân sách hiện có thì nên đi đâu?
- Chi phí di chuyển, lưu trú, ăn uống và vui chơi nên phân bổ thế nào?
- Lịch trình sáng, chiều, tối ra sao để thuận tiện về địa lý?
- Nên ăn gì, đi đâu và cần lưu ý điều gì?
- Làm cách nào để lưu hoặc chia sẻ kế hoạch cho người khác?

Quá trình này tốn thời gian, khó cân đối ngân sách và dễ tạo lịch trình thiếu thực tế. Sản phẩm giải quyết vấn đề bằng cách chuẩn hóa đầu vào, sử dụng AI để tổng hợp kế hoạch và trả về một cấu trúc nhất quán cho frontend.

## 3. Tầm nhìn sản phẩm

Trở thành nền tảng lập kế hoạch du lịch nhanh, dễ sử dụng và có chi phí vận hành thấp, giúp người dùng chuyển từ nhu cầu ban đầu sang một lịch trình có thể thực hiện trong vài phút.

## 4. Mục tiêu sản phẩm

### 4.1. Mục tiêu chính

- Tạo được kế hoạch du lịch đầy đủ từ một bộ tiêu chí ngắn gọn.
- Không để tổng chi phí AI đề xuất vượt ngân sách người dùng cung cấp.
- Cho phép sử dụng ngay cả khi chưa đăng ký tài khoản.
- Cho phép người dùng đã đăng nhập lưu, xem, chia sẻ và xóa kế hoạch của mình.
- Bảo vệ tài khoản bằng xác minh email, JWT, token revocation, OTP một lần và rate limiting.
- Duy trì chi phí thấp thông qua MongoDB, Gemini Flash-Lite và khả năng triển khai bằng Docker.

### 4.2. Chỉ số thành công đề xuất

Các chỉ số dưới đây là mục tiêu đo lường sản phẩm; hệ thống hiện chưa có module analytics riêng.

| Mã     | Chỉ số                                    | Mục tiêu ban đầu                                  |
| ------ | ----------------------------------------- | ------------------------------------------------- |
| KPI-01 | Tỷ lệ yêu cầu tạo kế hoạch thành công     | ≥ 95% khi Gemini và MongoDB hoạt động bình thường |
| KPI-02 | Tỷ lệ kế hoạch không vượt ngân sách       | 100% sau bước kiểm tra backend                    |
| KPI-03 | Tỷ lệ kết quả có đúng số ngày yêu cầu     | 100% sau bước kiểm tra backend                    |
| KPI-04 | Thời gian phản hồi tạo kế hoạch P95       | ≤ 30 giây, phụ thuộc Gemini                       |
| KPI-05 | Tỷ lệ API không liên quan AI phản hồi P95 | ≤ 1 giây trong điều kiện tải bình thường          |
| KPI-06 | Tỷ lệ test bắt buộc qua CI                | 100% trước khi hợp nhất PR                        |
| KPI-07 | Lỗ hổng dependency mức cao/nghiêm trọng   | 0 tại thời điểm phát hành                         |

## 5. Đối tượng sử dụng

### 5.1. Khách vãng lai

Người muốn thử nhanh chức năng lập kế hoạch mà không tạo tài khoản.

Nhu cầu chính:

- Nhập tiêu chí và nhận lịch trình.
- Xem các kế hoạch công khai.
- Mở lại hoặc xóa kế hoạch bằng ID và guest token.

Giới hạn:

- Không có danh sách lịch sử cá nhân.
- Không thể bật chia sẻ công khai trước khi nhận kế hoạch vào tài khoản.
- Có thể claim kế hoạch vào tài khoản; kế hoạch chưa claim tự hết hạn theo cấu hình.

### 5.2. Người dùng đã đăng ký

Người muốn quản lý kế hoạch lâu dài và kiểm soát quyền riêng tư.

Nhu cầu chính:

- Xác minh email và đăng nhập an toàn.
- Tạo kế hoạch riêng tư gắn với tài khoản.
- Xem lịch sử cá nhân theo phân trang.
- Chia sẻ hoặc thu hồi chia sẻ kế hoạch.
- Xóa kế hoạch của chính mình.
- Cập nhật hồ sơ và quản lý mật khẩu.

### 5.3. Quản trị viên vận hành

Vai trò `admin` đã tồn tại trong mô hình dữ liệu nhưng phiên bản hiện tại chưa cung cấp API quản trị. Quản trị viên vận hành hệ thống thông qua hạ tầng, log, MongoDB và cấu hình môi trường.

## 6. Phạm vi sản phẩm

### 6.1. Trong phạm vi phiên bản hiện tại

- Đăng ký tài khoản local bằng email và mật khẩu.
- Xác minh email bằng liên kết JWT dùng một lần.
- Gửi lại email xác minh theo cơ chế không làm lộ trạng thái tài khoản.
- Đăng nhập và cấp access token, refresh token.
- Làm mới access token.
- Thu hồi token khi đổi mật khẩu hoặc đăng xuất.
- Xem và cập nhật hồ sơ.
- Quên mật khẩu bằng OTP sáu chữ số và reset token dùng một lần.
- Tạo kế hoạch bằng Gemini với structured output.
- Kiểm tra số ngày và ngân sách trước khi lưu.
- Lưu kế hoạch của khách hoặc người dùng vào MongoDB.
- Danh sách kế hoạch cá nhân và công khai có phân trang.
- Kiểm soát quyền xem kế hoạch riêng tư.
- Bật hoặc tắt chia sẻ kế hoạch.
- Xóa kế hoạch thuộc sở hữu của người dùng.
- Health check cho API, MongoDB và trạng thái cấu hình Gemini.
- Rate limiting, validation DTO, CORS và logging HTTP.
- Unit test, E2E API test, CI và Docker build workflow.

### 6.2. Ngoài phạm vi hiện tại

- Frontend web hoặc mobile.
- Đặt vé máy bay, khách sạn, nhà hàng hoặc thanh toán.
- Đồng bộ giá theo thời gian thực từ nhà cung cấp du lịch.
- Bản đồ, định tuyến GPS hoặc tính khoảng cách thực tế.
- Đăng nhập Google, Facebook, Apple hoặc OAuth khác.
- Cộng tác chỉnh sửa kế hoạch theo thời gian thực.
- Bình luận, đánh giá, yêu thích hoặc theo dõi người dùng.
- Thông báo đẩy, SMS và lịch nhắc chuyến đi.
- API quản trị người dùng, nội dung hoặc thống kê.
- Chỉnh sửa thủ công nội dung từng ngày của kế hoạch.
- Đa tiền tệ và bản địa hóa hoàn chỉnh.
- Cam kết giá hoặc tính chính xác tuyệt đối của dữ liệu do AI sinh.

## 7. Nguyên tắc nghiệp vụ

| Mã    | Quy tắc                                                                                                |
| ----- | ------------------------------------------------------------------------------------------------------ |
| BR-01 | Email được chuẩn hóa bằng cách trim và chuyển thành chữ thường trước khi lưu hoặc tìm kiếm.            |
| BR-02 | Email và username phải duy nhất.                                                                       |
| BR-03 | Tài khoản mới ở trạng thái chưa kích hoạt và không được đăng nhập trước khi xác minh email.            |
| BR-04 | Tài khoản bị khóa không được đăng nhập, dùng access token hoặc refresh token.                          |
| BR-05 | Liên kết xác minh email chỉ được dùng một lần; gửi liên kết mới làm token trước đó mất hiệu lực.       |
| BR-06 | Mật khẩu dài từ 8 đến 20 ký tự và chỉ được lưu dưới dạng bcrypt hash.                                  |
| BR-07 | Refresh token chỉ lưu dưới dạng bcrypt hash. Backend không lưu token gốc.                              |
| BR-08 | Đổi mật khẩu, reset mật khẩu hoặc đăng xuất làm tăng `refreshTokenVersion`, khiến token cũ bị thu hồi. |
| BR-09 | Mỗi user và mỗi mục đích chỉ có một OTP chưa dùng mới nhất; OTP cũ bị xóa khi tạo OTP mới.             |
| BR-10 | OTP gồm đúng sáu chữ số, được hash, có hạn sử dụng và chỉ được dùng một lần.                           |
| BR-11 | Yêu cầu quên mật khẩu và gửi lại xác minh không được tiết lộ email có tồn tại hay không.               |
| BR-12 | Ngân sách đầu vào tối thiểu 100.000 VNĐ và tối đa 1 tỷ VNĐ.                                            |
| BR-13 | Ngân sách có thể là tổng đoàn (`total`) hoặc trên mỗi người (`per_person`).                            |
| BR-14 | Số người từ 1 đến 100; số ngày từ 1 đến 14; số đêm từ 0 đến 14.                                        |
| BR-15 | Nếu không nhập số đêm, hệ thống dùng `max(0, số ngày - 1)`.                                            |
| BR-16 | Nếu không nhập điểm đến, AI được phép đề xuất điểm đến phù hợp.                                        |
| BR-17 | Kế hoạch AI phải có đúng số ngày yêu cầu.                                                              |
| BR-18 | `totalEstimated` phải là số hữu hạn, không âm và không vượt tổng ngân sách của đoàn.                   |
| BR-19 | Kế hoạch của user đăng nhập mặc định là riêng tư.                                                      |
| BR-20 | Kế hoạch guest mặc định riêng tư, có TTL và chỉ truy cập/xóa được bằng guest token hợp lệ.             |
| BR-21 | Chỉ chủ sở hữu mới được bật/tắt chia sẻ hoặc xóa kế hoạch.                                             |
| BR-22 | Kế hoạch riêng tư chỉ chủ sở hữu có access token hợp lệ mới xem được.                                  |
| BR-23 | Kế hoạch công khai có thể được xem mà không cần đăng nhập.                                             |
| BR-24 | `userId` không được trả ra trong JSON của kế hoạch.                                                    |

## 8. Hành trình người dùng chính

### 8.1. Khách tạo kế hoạch

1. Khách nhập ngân sách, số người, điểm xuất phát, số ngày và các tùy chọn.
2. Backend kiểm tra dữ liệu đầu vào và giới hạn tần suất.
3. Backend quy đổi ngân sách tổng nếu người dùng nhập ngân sách trên mỗi người.
4. Gemini tạo kế hoạch theo JSON Schema.
5. Backend kiểm tra cấu trúc cơ bản, số ngày và tổng ngân sách.
6. Kế hoạch được lưu không có `userId`, `isPublic = false` và có thời hạn.
7. API trả về ID, chi tiết và guest token một lần để truy cập, xóa hoặc claim.

### 8.2. Đăng ký và xác minh tài khoản

1. Người dùng gửi email, username, mật khẩu và tên.
2. Backend kiểm tra tính duy nhất và hash mật khẩu.
3. Tài khoản được tạo với `isActive = false`.
4. Backend tạo mã nhận dạng xác minh dùng một lần, lưu bản hash và gửi email.
5. Người dùng mở liên kết xác minh.
6. Backend xác thực JWT và mã dùng một lần, sau đó kích hoạt tài khoản.
7. Người dùng có thể đăng nhập.

### 8.3. Người dùng tạo và quản lý kế hoạch

1. Người dùng đăng nhập để nhận access token và refresh token.
2. Người dùng tạo kế hoạch với access token.
3. Kế hoạch được gắn với user và mặc định riêng tư.
4. Người dùng xem lịch sử tại `my-trips`.
5. Người dùng có thể bật chia sẻ để kế hoạch xuất hiện trong danh sách công khai.
6. Người dùng có thể tắt chia sẻ hoặc xóa kế hoạch.

### 8.4. Quên mật khẩu

1. Người dùng nhập email.
2. API luôn trả thông báo trung tính.
3. Nếu email tồn tại, backend tạo OTP sáu chữ số, lưu bản hash và gửi email.
4. Người dùng xác minh OTP để nhận reset token thời hạn ngắn.
5. Người dùng gửi mật khẩu mới kèm reset token.
6. Backend đổi mật khẩu và tăng token version.
7. Reset token, access token và refresh token cũ không còn sử dụng được.

## 9. Epic và yêu cầu sản phẩm

### EPIC-01: Quản lý danh tính

- PR-01: Người dùng có thể đăng ký bằng email duy nhất.
- PR-02: Người dùng phải xác minh email trước khi đăng nhập.
- PR-03: Người dùng có thể gửi lại email xác minh.
- PR-04: Người dùng đã kích hoạt có thể đăng nhập và nhận hai loại token.
- PR-05: Người dùng có thể làm mới access token bằng refresh token hợp lệ.
- PR-06: Người dùng có thể đăng xuất và thu hồi token hiện tại.
- PR-07: Tài khoản bị khóa hoặc chưa kích hoạt không được truy cập tài nguyên bảo vệ.

### EPIC-02: Hồ sơ và mật khẩu

- PR-08: Người dùng có thể xem hồ sơ của chính mình.
- PR-09: Người dùng có thể cập nhật các trường hồ sơ được cho phép.
- PR-10: Người dùng có thể đổi mật khẩu sau khi nhập đúng mật khẩu cũ.
- PR-11: Người dùng có thể khôi phục mật khẩu bằng OTP và reset token.
- PR-12: Mọi token cũ bị thu hồi sau thay đổi mật khẩu.

### EPIC-03: Lập kế hoạch bằng AI

- PR-13: Khách và user đều có thể tạo kế hoạch.
- PR-14: Đầu vào hỗ trợ ngân sách tổng hoặc ngân sách trên mỗi người.
- PR-15: AI trả về điểm đến, phân bổ ngân sách, lịch trình, địa điểm gợi ý và mẹo du lịch.
- PR-16: Backend từ chối kết quả sai số ngày hoặc vượt ngân sách.
- PR-17: Hệ thống lưu cả tiêu chí đầu vào và kết quả AI.

### EPIC-04: Lịch sử và chia sẻ

- PR-18: User xem được lịch sử cá nhân theo trang.
- PR-19: Mọi người xem được danh sách kế hoạch công khai theo trang.
- PR-20: Chủ sở hữu kiểm soát trạng thái chia sẻ.
- PR-21: Chủ sở hữu xóa được kế hoạch của mình.
- PR-22: Người không phải chủ sở hữu không truy cập được kế hoạch riêng tư.

### EPIC-05: Vận hành và chất lượng

- PR-23: Hệ thống cung cấp health check.
- PR-24: API có validation và rate limiting.
- PR-25: CI chạy unit test khi có PR vào `dev` hoặc `main`.
- PR-26: CI chính chạy lint, unit test, E2E và build.
- PR-27: Docker publish chỉ chạy khi được kích hoạt thủ công.

## 10. Tiêu chí nghiệm thu cấp sản phẩm

### 10.1. Tài khoản

- Không thể đăng ký hai tài khoản cùng email hoặc username.
- Không thể đăng nhập khi chưa xác minh email.
- Liên kết xác minh không thể dùng lần thứ hai.
- Refresh token sai, hết hạn, đã bị thay thế hoặc sai version phải bị từ chối.
- Sau đổi/reset mật khẩu, access token cũ không truy cập được profile.

### 10.2. Lập kế hoạch

- Payload không hợp lệ bị trả lỗi 400 trước khi gọi Gemini.
- Kết quả lưu có đầy đủ destination, budget breakdown, itinerary, recommended spots và travel tips.
- Số phần tử itinerary bằng số ngày yêu cầu.
- Tổng chi phí không vượt ngân sách tổng.
- Kế hoạch guest và kế hoạch user đều riêng tư mặc định; chỉ owner mới bật công khai.

### 10.3. Phân quyền

- Anonymous xem được kế hoạch công khai.
- Anonymous hoặc user khác nhận lỗi khi xem kế hoạch riêng tư.
- User khác không thể chia sẻ hoặc xóa kế hoạch không thuộc sở hữu.
- `userId` không xuất hiện trong JSON trả về của kế hoạch.

### 10.4. Chất lượng phát hành

- Lint và build thành công.
- Toàn bộ unit test và E2E test thành công.
- Không có dependency vulnerability mức đã biết tại thời điểm kiểm tra.
- PR vào `dev` hoặc `main` kích hoạt action unit test.

## 11. Ràng buộc và giả định

- Chất lượng nội dung phụ thuộc Gemini và độ rõ ràng của đầu vào.
- Chi phí, địa chỉ và giờ hoạt động do AI cung cấp chỉ mang tính tham khảo.
- Hệ thống không gọi nguồn giá hoặc bản đồ theo thời gian thực.
- Người dùng cần tự kiểm tra thông tin quan trọng trước chuyến đi.
- Một tài khoản chỉ lưu một refresh token đang hoạt động tại một thời điểm; đăng nhập mới có thể làm refresh token cũ không dùng được.
- Rate limit hiện lưu trong bộ nhớ tiến trình, phù hợp triển khai một instance; khi scale ngang cần kho dùng chung như Redis.
- Email cần SMTP hoặc Resend được cấu hình đúng.
- MongoDB và Gemini là phụ thuộc ngoài bắt buộc cho luồng lập kế hoạch đầy đủ.

## 12. Rủi ro sản phẩm và hướng giảm thiểu

| Rủi ro                                           | Mức độ     | Giảm thiểu hiện tại/đề xuất                                                  |
| ------------------------------------------------ | ---------- | ---------------------------------------------------------------------------- |
| AI tạo thông tin không chính xác                 | Cao        | JSON Schema, kiểm tra ngân sách/số ngày, hiển thị cảnh báo dữ liệu tham khảo |
| Gemini hết quota hoặc gián đoạn                  | Cao        | Timeout rõ ràng, quota ngày theo user/IP; fallback model để bổ sung sau      |
| Email không gửi được                             | Trung bình | Hỗ trợ SMTP/Resend; endpoint gửi lại; cần monitoring email                   |
| Mất guest token                                  | Trung bình | Token chỉ trả một lần; user nên claim kế hoạch nếu muốn lưu lâu dài          |
| Chi phí AI tăng khi bị lạm dụng                  | Cao        | Rate limit ngắn hạn và quota ngày lưu trong MongoDB theo user/IP             |
| Rate limit mất hiệu lực khi nhiều instance       | Trung bình | Chuyển storage sang Redis khi scale ngang                                    |
| Dữ liệu AI dạng object khó truy vấn sâu          | Thấp       | Phù hợp MVP; tách sub-schema khi cần analytics/search                        |
| Không có quy trình moderation nội dung công khai | Trung bình | Bổ sung report/moderation/admin API trong roadmap                            |

## 13. Roadmap đề xuất

### Giai đoạn 1: Ổn định MVP

- Bổ sung retry có backoff/circuit breaker khi lưu lượng thực tế yêu cầu.
- Theo dõi latency, error rate và chi phí AI trên dashboard khi deploy public.
- Hiển thị điều khoản rằng dữ liệu AI chỉ mang tính tham khảo.

### Giai đoạn 2: Nâng trải nghiệm

- Chỉnh sửa và sao chép kế hoạch.
- Tìm kiếm/lọc kế hoạch công khai.
- Yêu thích và lưu kế hoạch công khai vào tài khoản.
- Xuất PDF hoặc lịch.
- Hỗ trợ ảnh đại diện upload qua object storage.

### Giai đoạn 3: Dữ liệu thực tế và cộng tác

- Tích hợp bản đồ, khoảng cách và thời gian di chuyển.
- Tích hợp nguồn địa điểm, giá và giờ hoạt động.
- Cộng tác nhóm, chia sẻ bằng mã/link có quyền.
- Notification và nhắc lịch.
- Dashboard quản trị và moderation.

## 14. Quyết định sản phẩm cần theo dõi

| Mã     | Quyết định hiện tại             | Ghi chú                                                    |
| ------ | ------------------------------- | ---------------------------------------------------------- |
| DEC-01 | Guest plan riêng tư và có TTL   | Quản lý bằng guest token; có thể claim vào tài khoản       |
| DEC-02 | Một refresh token cho mỗi user  | Đơn giản, chi phí thấp; chưa hỗ trợ quản lý nhiều thiết bị |
| DEC-03 | Dùng Gemini Flash-Lite mặc định | Ưu tiên free tier/chi phí và structured output             |
| DEC-04 | MongoDB lưu nested result       | Phù hợp dữ liệu kế hoạch linh hoạt và MVP                  |
| DEC-05 | Email qua SMTP hoặc Resend      | Cho phép chọn nhà cung cấp theo chi phí triển khai         |

## 15. Tài liệu liên quan

- [SRS – Software Requirements Specification](./SRS.md)
- [API Documentation](./API.md)
- [Project Structure & Architecture](./STRUCTURE.md)
- [Environment example](../.env.example)
