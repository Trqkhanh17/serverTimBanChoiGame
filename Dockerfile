# 1. SETUP: Chọn "Hệ điều hành" nền (Base Image)
# Chúng ta dùng node:20-alpine vì nó siêu nhẹ (Linux Alpine) và đã cài sẵn Node.js v20.
FROM node:20-alpine

# 2. FOLDER: Tạo thư mục làm việc bên trong Container
# Mọi lệnh sau dòng này sẽ chạy trong thư mục /app của Container
WORKDIR /app

# 3. CACHING: Copy file định nghĩa thư viện trước
# Tại sao? Vì Docker có cơ chế cache theo layer. 
# Nếu bạn chỉ sửa code (src/...) mà không sửa package.json, Docker sẽ bỏ qua bước npm install (lấy từ cache), giúp build siêu nhanh.
COPY package*.json ./

# 4. INSTALL: Cài đặt thư viện
RUN npm install

# 5. CODE: Copy toàn bộ source code của bạn vào Container
# (Trừ những file trong .dockerignore như node_modules, .git...)
COPY . .

# 6. BUILD: Chuyển đổi TypeScript sang JavaScript (thư mục dist)
RUN npm run build

# 7. NETWORK: Thông báo Container này sẽ "lắng nghe" ở port 8080
# (Lưu ý: Chỉ là thông báo, cần map port lúc chạy container mới truy cập được)
EXPOSE 8080

# 8. START: Lệnh chạy chính thức khi Container khởi động
CMD ["npm", "run", "start:prod"]
