# AI Travel Planner Documentation

Tài liệu trong thư mục này mô tả sản phẩm, nghiệp vụ, yêu cầu phần mềm, API và kiến trúc của backend.

| Tài liệu                    | Mục đích                                                                | Đối tượng chính                  |
| --------------------------- | ----------------------------------------------------------------------- | -------------------------------- |
| [PRD](./PRD.md)             | Bài toán sản phẩm, phạm vi, personas, quy tắc nghiệp vụ, KPI, roadmap   | Product Owner, BA, Developer, QA |
| [SRS](./SRS.md)             | Yêu cầu chức năng/phi chức năng, dữ liệu, bảo mật, lỗi và truy vết test | Developer, QA, DevOps            |
| [API](./API.md)             | Endpoint, request/response và cách gọi API                              | Frontend, Mobile, Integration    |
| [Structure](./STRUCTURE.md) | Cấu trúc source code và kiến trúc module                                | Developer, Reviewer              |

## Thứ tự đọc đề xuất

1. Đọc PRD để hiểu người dùng, bài toán và quy tắc nghiệp vụ.
2. Đọc SRS để hiểu hành vi bắt buộc và tiêu chí kỹ thuật.
3. Dùng API Documentation khi tích hợp frontend hoặc kiểm thử thủ công.
4. Dùng Structure khi phát triển hoặc review code.

## Quy tắc cập nhật

- Thay đổi nghiệp vụ phải cập nhật PRD và mã quy tắc liên quan.
- Thay đổi endpoint, validation, status code, schema hoặc quyền phải cập nhật SRS và API.
- Thay đổi module/folder hoặc luồng phụ thuộc phải cập nhật Structure.
- Mọi tài liệu phải phân biệt rõ chức năng đã triển khai với roadmap.
