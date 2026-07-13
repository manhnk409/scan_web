# Sử dụng image Python 3.11 gọn nhẹ
FROM python:3.11-slim

# Cài đặt Nmap (bắt buộc phải có để module nmap_scan hoạt động) và dọn dẹp cache apt
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Đặt thư mục làm việc trong container
WORKDIR /app

# Sao chép file requirements.txt và cài đặt thư viện
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép toàn bộ mã nguồn vào container
COPY . .

# Đảm bảo có thư mục lưu báo cáo
RUN mkdir -p reports

# Mở cổng 8000
EXPOSE 8000

# Chạy server FastAPI bằng Uvicorn
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
