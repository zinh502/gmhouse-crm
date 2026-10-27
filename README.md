# GM-House CRM Pro v4.2

## Tài khoản quản trị khởi tạo
- Họ tên: Đào Thị Hồng Tiên
- Email: `Tien1207@gmail.com` (hệ thống tự chuẩn hóa thành chữ thường khi đăng nhập)
- Mật khẩu khởi tạo: `Tien1207`

Sau lần khởi tạo đầu tiên, mật khẩu được giữ nguyên khi tải lại trang hoặc khởi động ứng dụng. Admin có thể đổi mật khẩu trong nút **Đổi mật khẩu** ở thanh trên cùng.

## Chức năng Admin
- Xem/lọc khách hàng của toàn nhóm và xem dữ liệu theo từng thành viên.
- Tạo tài khoản, sửa tên/email, đổi quyền Admin/Thành viên, khóa/mở khóa, đặt lại mật khẩu và xóa tài khoản.
- Khi đổi email đăng nhập, cần nhập mật khẩu mới cùng lúc để hash mật khẩu khớp email mới.
- Khách hàng của tài khoản bị xóa được chuyển về Admin để tránh mất dữ liệu.
- Không cho tự khóa/hạ quyền/xóa tài khoản Admin đang đăng nhập và không cho xóa/hạ quyền Admin hoạt động cuối cùng.
- Đăng ký công khai chỉ tạo tài khoản Thành viên; chỉ Admin đã đăng nhập mới được tạo hoặc nâng quyền Admin.
- Tài khoản demo cũ `admin@gmhouse.vn` bị vô hiệu hóa; dữ liệu khách hàng thuộc tài khoản này được chuyển sang Admin mới khi ứng dụng khởi động.

## Cách chạy
Mở `index.html` bằng trình duyệt hoặc deploy như website tĩnh (ví dụ Vercel). Không cần cài package riêng cho phiên bản hiện tại.

## Lưu ý quan trọng về dữ liệu và bảo mật
Phiên bản source hiện tại dùng `localStorage`/`IndexedDB` trong trình duyệt, chưa có backend và cơ sở dữ liệu dùng chung. Vì vậy dữ liệu/tài khoản không tự đồng bộ giữa các trình duyệt hoặc thiết bị; quyền kiểm tra ở frontend không đủ để bảo vệ CRM khi triển khai công khai. Nếu dùng dữ liệu khách thuê thật cho nhiều nhân viên/thiết bị, cần bổ sung backend xác thực và database phía máy chủ, lưu mật khẩu bằng thuật toán chuyên dụng như Argon2id/bcrypt và kiểm tra quyền ở mọi API.
