/**
 * ============================================================================
 * GMHouseDB v4.2 — Thư viện Quản lý Dữ liệu, Phân quyền RBAC (Admin/Member) & Bảo mật
 * Kiến trúc: Multi-Tenant In-Memory Cache (O(1)) + IndexedDB + LocalStorage Mirror
 * Tính năng mới v4.2:
 *  - Đổi mật khẩu người dùng (Xác thực mật khẩu cũ + SHA-256 Hash)
 *  - Phân quyền RBAC: Admin (Toàn quyền hệ thống + Không gian cá nhân riêng) & Member (Cô lập dữ liệu 100%)
 *  - Admin User CRUD: Tạo user, Sửa tên/quyền, Đặt lại mật khẩu, Khóa/Mở khóa, Xóa user & Chuyển giao khách
 *  - Admin Team Query & CSV Export: Xem/Lọc khách hàng theo từng thành viên hoặc toàn team, xuất CSV in ấn
 * ============================================================================
 */

class GMHouseDataEngine {
  constructor(options = {}) {
    this.dbName = options.dbName || 'GMHouse_Enterprise_DB_v4';
    this.dbVersion = options.dbVersion || 2;

    // Bộ nhớ đệm O(1) chứa toàn bộ bản ghi trên thiết bị (Được bảo vệ bởi tầng kiểm soát quyền RBAC)
    this.allRecordsMap = new Map();
    this.usersMap = new Map();
    this.currentUser = null;
    this.listeners = new Set();
    this.undoStack = [];
    this.idb = null;

    this.SCHEMA = {
      STATUSES: {
        uu_tien_1: { label: 'Ưu tiên 1', color: '#854d0e', bg: '#fef9c3', border: '#fde047', dot: '#eab308', order: 1 },
        uu_tien_2: { label: 'Ưu tiên 2', color: '#9a3412', bg: '#ffedd5', border: '#fdba74', dot: '#f97316', order: 2 },
        da_chot:   { label: 'Đã chốt',   color: '#166534', bg: '#dcfce7', border: '#86efac', dot: '#22c55e', order: 3 },
        rot:       { label: 'Rớt',       color: '#991b1b', bg: '#fee2e2', border: '#fca5a5', dot: '#ef4444', order: 4 }
      },
      SOURCES: [
        'Facebook', 'Khách cũ', 'Marketplace', 'TikTok',
        'Threads', 'Bất động sản', 'Chợ tốt', 'Nhận pass/Pass cho', 'Khác'
      ],
      AREAS: [
        'Bình Thạnh', 'Phú Nhuận', 'Q1', 'Q2', 'Q3', 'Gò Vấp', 'Tân Bình', 'Khác'
      ]
    };
  }

  /* ── 1. KHỞI TẠO HỆ THỐNG & ĐỒNG BỘ DỮ LIỆU ── */
  async init() {
    try {
      this.idb = await this._openIndexedDB();
    } catch (e) {
      console.warn('[GMHouseDB] Chạy ở chế độ LocalStorage Mirror:', e);
    }
    await this._loadAllUsers();
    await this._ensureDefaultAdminExists();
    await this._loadAllCustomersIntoCache();
    await this._migrateLegacyAdminCustomers();
    await this._restoreSession();
    return this;
  }

  _openIndexedDB() {
    return new Promise((resolve, reject) => {
      if (!window.indexedDB) return reject(new Error('No IndexedDB'));
      const req = indexedDB.open(this.dbName, this.dbVersion);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('users')) {
          db.createObjectStore('users', { keyPath: 'uid' });
        }
        if (!db.objectStoreNames.contains('customers')) {
          const store = db.createObjectStore('customers', { keyPath: 'id' });
          store.createIndex('ownerUid', 'ownerUid', { unique: false });
          store.createIndex('ngayVe', 'ngayVe', { unique: false });
        }
      };
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror = (e) => reject(e.target.error);
    });
  }

  /* ── 2. MÃ HÓA SHA-256 & QUẢN LÝ TÀI KHOẢN / ĐỔI MẬT KHẨU ── */
  async hashPassword(password, salt = 'gmhouse_salt_2026') {
    if (window.crypto && window.crypto.subtle) {
      const msgBuffer = new TextEncoder().encode(password + ':' + salt);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    let hash = 0, str = password + ':' + salt;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return 'fb_' + Math.abs(hash).toString(16);
  }

  async _ensureDefaultAdminExists() {
    // Tạo tài khoản quản trị chính một lần. Ghi nhớ UID để việc đổi email/tên
    // không khiến ứng dụng vô tình tạo lại tài khoản mặc định ở lần mở sau.
    const adminEmail = 'tien1207@gmail.com';
    const seedMarker = 'gmhouse_primary_admin_seeded_v1';
    const adminUidKey = 'gmhouse_primary_admin_uid_v1';
    const firstSetup = localStorage.getItem(seedMarker) !== '1';
    const storedAdminUid = localStorage.getItem(adminUidKey);
    let rootAdmin = storedAdminUid ? this.usersMap.get(storedAdminUid) : null;

    if (!rootAdmin) {
      rootAdmin = Array.from(this.usersMap.values()).find(
        u => (u.email || '').trim().toLowerCase() === adminEmail
      );
    }

    if (!rootAdmin) {
      let uid = 'usr_admin_tien';
      if (this.usersMap.has(uid)) uid += '_' + Date.now().toString(36);
      rootAdmin = {
        uid,
        email: adminEmail,
        name: 'Đào Thị Hồng Tiên',
        role: 'admin',
        active: true,
        passwordHash: await this.hashPassword('Tien1207', adminEmail),
        createdAt: new Date().toISOString()
      };
      this.usersMap.set(rootAdmin.uid, rootAdmin);
    } else {
      // Chỉ đặt thông tin mặc định lúc nâng cấp lần đầu, không ghi đè các thay đổi sau đó.
      if (firstSetup) {
        rootAdmin.email = adminEmail;
        rootAdmin.name = 'Đào Thị Hồng Tiên';
        rootAdmin.role = 'admin';
        rootAdmin.active = true;
      }
      if (firstSetup || !rootAdmin.passwordHash) {
        rootAdmin.passwordHash = await this.hashPassword('Tien1207', rootAdmin.email || adminEmail);
      }
      rootAdmin.updatedAt = new Date().toISOString();
      this.usersMap.set(rootAdmin.uid, rootAdmin);
    }

    // Vô hiệu hóa tài khoản demo cũ admin@gmhouse.vn / admin123 để tránh đăng nhập bằng mật khẩu mẫu.
    // Khách hàng thuộc tài khoản cũ sẽ được chuyển sang Admin mới sau khi nạp dữ liệu.
    for (const user of this.usersMap.values()) {
      if ((user.email || '').trim().toLowerCase() === 'admin@gmhouse.vn') {
        user.role = 'member';
        user.active = false;
        user.updatedAt = new Date().toISOString();
        this.usersMap.set(user.uid, user);
      }
    }

    await this._persistUsers();
    localStorage.setItem(adminUidKey, rootAdmin.uid);
    localStorage.setItem(seedMarker, '1');
  }

  async _migrateLegacyAdminCustomers() {
    const storedAdminUid = localStorage.getItem('gmhouse_primary_admin_uid_v1');
    const admin = (storedAdminUid ? this.usersMap.get(storedAdminUid) : null) ||
      Array.from(this.usersMap.values()).find(
        u => (u.email || '').trim().toLowerCase() === 'tien1207@gmail.com' && u.role === 'admin'
      );
    if (!admin) return;

    const legacyAdminUids = new Set(
      Array.from(this.usersMap.values())
        .filter(u => u.uid !== admin.uid && (
          u.uid === 'usr_root_admin' ||
          (u.email || '').trim().toLowerCase() === 'admin@gmhouse.vn'
        ))
        .map(u => u.uid)
    );

    let changed = false;
    for (const [recordId, record] of this.allRecordsMap.entries()) {
      if (!legacyAdminUids.has(record.ownerUid)) continue;
      const migrated = this._normalizeRecord({
        ...record,
        ownerUid: admin.uid,
        ownerName: admin.name,
        ownerEmail: admin.email
      }, admin.uid);
      this.allRecordsMap.set(recordId, migrated);
      changed = true;
    }

    if (changed) await this._persistAllCustomers();
  }

  async register({ name, email, password }) {
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !password) throw new Error('Vui lòng nhập đầy đủ Email và Mật khẩu.');
    if (password.length < 6) throw new Error('Mật khẩu phải có tối thiểu 6 ký tự.');

    for (const u of this.usersMap.values()) {
      if (u.email === cleanEmail) {
        throw new Error('Email này đã được đăng ký. Vui lòng chọn Đăng nhập.');
      }
    }

    const role = 'member';

    const passwordHash = await this.hashPassword(password, cleanEmail);
    const user = {
      uid: 'usr_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6),
      email: cleanEmail,
      name: (name || cleanEmail.split('@')[0]).trim(),
      role,
      active: true,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    this.usersMap.set(user.uid, user);
    await this._persistUsers();
    await this._setSession(user);
    return this.getSafeUser();
  }

  async login({ email, password }) {
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !password) throw new Error('Vui lòng nhập Email và Mật khẩu.');

    let foundUser = null;
    for (const u of this.usersMap.values()) {
      if (u.email === cleanEmail) {
        foundUser = u;
        break;
      }
    }
    if (!foundUser) throw new Error('Tài khoản không tồn tại. Vui lòng kiểm tra lại Email.');
    if (foundUser.active === false) throw new Error('Tài khoản này đang tạm khóa bởi Admin.');

    const passwordHash = await this.hashPassword(password, cleanEmail);
    if (foundUser.passwordHash !== passwordHash) {
      throw new Error('Mật khẩu không chính xác.');
    }

    await this._setSession(foundUser);
    return this.getSafeUser();
  }

  async logout() {
    this.currentUser = null;
    this.undoStack = [];
    localStorage.removeItem('gmhouse_active_session');
    this._notify('auth_changed');
  }

  /* ── TÍNH NĂNG ĐỔI MẬT KHẨU CHO USER ── */
  async changeMyPassword({ oldPassword, newPassword }) {
    if (!this.currentUser) throw new Error('Bạn chưa đăng nhập.');
    if (!oldPassword || !newPassword) throw new Error('Vui lòng nhập đầy đủ mật khẩu hiện tại và mật khẩu mới.');
    if (newPassword.length < 6) throw new Error('Mật khẩu mới phải có ít nhất 6 ký tự.');

    const userRecord = this.usersMap.get(this.currentUser.uid);
    if (!userRecord) throw new Error('Không tìm thấy dữ liệu tài khoản.');

    const oldHash = await this.hashPassword(oldPassword, userRecord.email);
    if (userRecord.passwordHash !== oldHash) {
      throw new Error('Mật khẩu hiện tại không chính xác!');
    }

    userRecord.passwordHash = await this.hashPassword(newPassword, userRecord.email);
    userRecord.updatedAt = new Date().toISOString();
    this.usersMap.set(userRecord.uid, userRecord);
    await this._persistUsers();
    this._notify('password_changed');
    return true;
  }

  /* ── 3. CÁC QUYỀN QUẢN TRỊ USER CỦA ADMIN (ADMIN USER CRUD) ── */
  _requireAdmin() {
    if (!this.currentUser || this.currentUser.role !== 'admin') {
      throw new Error('Truy cập bị từ chối: Chức năng này chỉ dành cho Quản trị viên (Admin).');
    }
  }

  isAdmin() {
    return Boolean(this.currentUser && this.currentUser.role === 'admin');
  }

  getSafeUser(userObj = this.currentUser) {
    if (!userObj) return null;
    const { passwordHash, ...safe } = userObj;
    return safe;
  }

  getMemberByUid(uid) {
    const u = this.usersMap.get(uid);
    return u ? this.getSafeUser(u) : null;
  }

  listAllRegisteredMembers() {
    return Array.from(this.usersMap.values()).map(u => this.getSafeUser(u));
  }

  async adminCreateUser({ name, email, password, role = 'member' }) {
    this._requireAdmin();
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !password) throw new Error('Vui lòng nhập Email và Mật khẩu.');
    if (password.length < 6) throw new Error('Mật khẩu phải từ 6 ký tự trở lên.');

    for (const u of this.usersMap.values()) {
      if (u.email === cleanEmail) throw new Error('Email này đã tồn tại trong hệ thống.');
    }

    const passwordHash = await this.hashPassword(password, cleanEmail);
    const newUser = {
      uid: 'usr_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6),
      email: cleanEmail,
      name: (name || cleanEmail.split('@')[0]).trim(),
      role: role === 'admin' ? 'admin' : 'member',
      active: true,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    this.usersMap.set(newUser.uid, newUser);
    await this._persistUsers();
    this._notify('users_updated');
    return this.getSafeUser(newUser);
  }

  async adminUpdateUser(targetUid, { name, email, role, active, newPassword = '' }) {
    this._requireAdmin();
    const user = this.usersMap.get(targetUid);
    if (!user) throw new Error('Không tìm thấy thành viên này.');

    const cleanEmail = (email === undefined ? user.email : (email || '')).trim().toLowerCase();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      throw new Error('Vui lòng nhập email hợp lệ.');
    }
    const emailChanged = cleanEmail !== (user.email || '').trim().toLowerCase();
    for (const other of this.usersMap.values()) {
      if (other.uid !== targetUid && (other.email || '').trim().toLowerCase() === cleanEmail) {
        throw new Error('Email này đã được một tài khoản khác sử dụng.');
      }
    }

    if (emailChanged && !newPassword) {
      throw new Error('Khi đổi email đăng nhập, Admin cần đặt mật khẩu mới để tài khoản có thể đăng nhập bằng email mới.');
    }
    if (newPassword && newPassword.length < 6) {
      throw new Error('Mật khẩu mới phải có tối thiểu 6 ký tự.');
    }

    if (role !== undefined && (role === 'admin' || role === 'member')) {
      if (targetUid === this.currentUser.uid && role !== 'admin') {
        throw new Error('Bạn không thể tự thu hồi quyền Admin của chính mình.');
      }
      if (user.role === 'admin' && role !== 'admin') {
        const hasOtherActiveAdmin = Array.from(this.usersMap.values()).some(
          candidate => candidate.uid !== targetUid && candidate.role === 'admin' && candidate.active !== false
        );
        if (!hasOtherActiveAdmin) throw new Error('Không thể hạ quyền Admin cuối cùng trong hệ thống.');
      }
      user.role = role;
    }

    if (active !== undefined) {
      if (targetUid === this.currentUser.uid && active === false) {
        throw new Error('Bạn không thể tự khóa tài khoản đang đăng nhập.');
      }
      if (user.role === 'admin' && active === false) {
        const hasOtherActiveAdmin = Array.from(this.usersMap.values()).some(
          candidate => candidate.uid !== targetUid && candidate.role === 'admin' && candidate.active !== false
        );
        if (!hasOtherActiveAdmin) throw new Error('Không thể khóa Admin đang hoạt động cuối cùng trong hệ thống.');
      }
      user.active = Boolean(active);
    }

    if (name !== undefined && name.trim()) user.name = name.trim();
    user.email = cleanEmail;
    if (newPassword) user.passwordHash = await this.hashPassword(newPassword, cleanEmail);
    user.updatedAt = new Date().toISOString();
    this.usersMap.set(targetUid, user);

    if (targetUid === this.currentUser.uid) {
      this.currentUser = user;
      localStorage.setItem('gmhouse_active_session', JSON.stringify(this.getSafeUser()));
    }
    await this._persistUsers();
    this._notify('users_updated');
    return this.getSafeUser(user);
  }

  async adminResetUserPassword(targetUid, newPassword) {
    this._requireAdmin();
    if (!newPassword || newPassword.length < 6) {
      throw new Error('Mật khẩu mới phải có tối thiểu 6 ký tự.');
    }
    const user = this.usersMap.get(targetUid);
    if (!user) throw new Error('Không tìm thấy thành viên.');

    user.passwordHash = await this.hashPassword(newPassword, user.email);
    user.updatedAt = new Date().toISOString();
    this.usersMap.set(targetUid, user);
    await this._persistUsers();
    this._notify('users_updated');
    return true;
  }

  async adminDeleteUser(targetUid, { transferCustomersToAdmin = true } = {}) {
    this._requireAdmin();
    if (targetUid === this.currentUser.uid) {
      throw new Error('Không thể xóa tài khoản Admin đang đăng nhập.');
    }
    const user = this.usersMap.get(targetUid);
    if (!user) throw new Error('Không tìm thấy thành viên.');
    if (user.role === 'admin') {
      const hasOtherActiveAdmin = Array.from(this.usersMap.values()).some(
        candidate => candidate.uid !== targetUid && candidate.role === 'admin' && candidate.active !== false
      );
      if (!hasOtherActiveAdmin) throw new Error('Không thể xóa Admin đang hoạt động cuối cùng trong hệ thống.');
    }

    // Xử lý danh sách khách hàng của thành viên bị xóa
    for (const [cid, record] of this.allRecordsMap.entries()) {
      if (record.ownerUid === targetUid) {
        if (transferCustomersToAdmin) {
          const updated = this._normalizeRecord({ ...record, ownerUid: this.currentUser.uid }, this.currentUser.uid);
          this.allRecordsMap.set(cid, updated);
        } else {
          this.allRecordsMap.delete(cid);
        }
      }
    }

    this.usersMap.delete(targetUid);
    await this._persistUsers();
    await this._persistAllCustomers();
    this._notify('users_updated');
    return true;
  }

  /* ── 4. QUẢN LÝ DỮ LIỆU KHÁCH HÀNG VỚI CÔ LẬP PHÂN QUYỀN (DATA ISOLATION) ── */
  _canAccessRecord(record) {
    if (!this.currentUser || !record) return false;
    if (this.currentUser.role === 'admin') return true;
    return record.ownerUid === this.currentUser.uid;
  }

  getRecordById(id) {
    const rec = this.allRecordsMap.get(id);
    if (!rec || !this._canAccessRecord(rec)) return null;
    return rec;
  }

  _normalizeRecord(raw, fallbackOwnerUid) {
    const now = new Date().toISOString();
    const ownerUid = raw.ownerUid || fallbackOwnerUid || (this.currentUser ? this.currentUser.uid : 'usr_root_admin');
    const ownerObj = this.usersMap.get(ownerUid);
    const ownerName = ownerObj ? ownerObj.name : (raw.ownerName || 'Thành viên');
    const ownerEmail = ownerObj ? ownerObj.email : (raw.ownerEmail || '');

    const record = {
      id:         String(raw.id || ('kh_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6))),
      ownerUid:   ownerUid,
      ownerName:  ownerName,
      ownerEmail: ownerEmail,
      ngayVe:     raw.ngayVe || now.split('T')[0],
      tenKhach:   (raw.tenKhach || '').trim(),
      sdt:        (raw.sdt || '').trim(),
      nguon:      raw.nguon || '',
      noteNguon:  raw.noteNguon || '',
      ngayO:      raw.ngayO || '',
      khuVuc:     raw.khuVuc || '',
      noteKhuVuc: raw.noteKhuVuc || '',
      taiChinh:   raw.taiChinh || '',
      tinhTrang:  this.SCHEMA.STATUSES[raw.tinhTrang] ? raw.tinhTrang : 'uu_tien_1',
      ghiChu:     raw.ghiChu || '',
      updatedAt:  raw.updatedAt || now
    };

    record._searchIndex = this._removeAccents(
      `${record.tenKhach} ${record.sdt} ${record.nguon} ${record.noteNguon} ${record.khuVuc} ${record.noteKhuVuc} ${record.taiChinh} ${record.ghiChu} ${record.ownerName} ${record.ownerEmail}`
    ).toLowerCase();
    return record;
  }

  _removeAccents(str) {
    return (str || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/đ/g, 'd')
      .replace(/Đ/g, 'D');
  }

  async upsert(customerData) {
    if (!this.currentUser) throw new Error('Chưa đăng nhập');
    const existing = customerData.id ? this.allRecordsMap.get(customerData.id) : null;

    if (existing && !this._canAccessRecord(existing)) {
      throw new Error('Bạn không có quyền chỉnh sửa khách hàng của thành viên khác.');
    }

    // Xác định ownerUid:
    // - Nếu là Member: luôn gán vào chính mình (this.currentUser.uid)
    // - Nếu là Admin: có thể chỉ định ownerUid (gán cho thành viên) hoặc giữ nguyên ownerUid cũ, mặc định là Admin
    let targetOwnerUid = this.currentUser.uid;
    if (this.isAdmin()) {
      targetOwnerUid = customerData.ownerUid || (existing ? existing.ownerUid : this.currentUser.uid);
    }

    if (existing) {
      this._pushUndo({ type: 'upsert', prev: { ...existing } });
    } else {
      const generatedId = String(customerData.id || ('kh_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6)));
      customerData = { ...customerData, id: generatedId };
      this._pushUndo({ type: 'insert', id: generatedId });
    }

    const record = this._normalizeRecord(
      { ...existing, ...customerData, ownerUid: targetOwnerUid, updatedAt: new Date().toISOString() },
      targetOwnerUid
    );

    this.allRecordsMap.set(record.id, record);
    await this._persistAllCustomers();
    this._notify('record_updated', record);
    return record;
  }

  async patch(id, partialData) {
    const existing = this.allRecordsMap.get(id);
    if (!existing) return null;
    if (!this._canAccessRecord(existing)) {
      throw new Error('Không có quyền thao tác.');
    }
    return this.upsert({ ...existing, ...partialData, id });
  }

  async remove(id) {
    const existing = this.allRecordsMap.get(id);
    if (!existing) return false;
    if (!this._canAccessRecord(existing)) {
      throw new Error('Bạn không có quyền xóa khách hàng của thành viên khác.');
    }
    this._pushUndo({ type: 'delete', prev: { ...existing } });
    this.allRecordsMap.delete(id);
    await this._persistAllCustomers();
    this._notify('record_deleted', id);
    return true;
  }

  async undoLastAction() {
    const last = this.undoStack.pop();
    if (!last || !this.currentUser) return false;
    if (last.type === 'delete' || last.type === 'upsert') {
      const norm = this._normalizeRecord(last.prev, last.prev.ownerUid);
      this.allRecordsMap.set(norm.id, norm);
    } else if (last.type === 'insert' && last.id) {
      this.allRecordsMap.delete(last.id);
    }
    await this._persistAllCustomers();
    this._notify('undo_executed');
    return true;
  }

  _pushUndo(action) {
    this.undoStack.push(action);
    if (this.undoStack.length > 25) this.undoStack.shift();
  }

  /* ── 5. BỘ TRUY VẤN TỐC ĐỘ CAO (HỖ TRỢ CẢ KHÔNG GIAN CÁ NHÂN & TRANG ADMIN) ── */
  query({
    scope = 'personal', // 'personal' (Không gian cá nhân) | 'admin_team' (Trang Admin xem toàn team/từng thành viên)
    memberUid = 'all',  // Dùng khi scope === 'admin_team': 'all' hoặc uid của từng thành viên
    viewMode = 'month',
    refDate = new Date().toISOString().split('T')[0],
    status = 'all',
    nguon = 'all',
    khuVuc = 'all',
    search = '',
    sortField = 'ngayVe',
    sortAsc = false
  } = {}) {
    if (!this.currentUser) {
      return { items: [], stats: { total: 0, totalScope: 0, uu_tien_1: 0, uu_tien_2: 0, da_chot: 0, rot: 0, conversionRate: 0 } };
    }

    // Bước 1: Cô lập dữ liệu theo phân quyền (Security Boundary)
    const allInSystem = Array.from(this.allRecordsMap.values());
    let scopedRecords = [];

    if (scope === 'admin_team' && this.isAdmin()) {
      scopedRecords = allInSystem.filter(c => memberUid === 'all' || c.ownerUid === memberUid);
    } else {
      // Chế độ cá nhân (Dành cho cả Member lẫn Không gian cá nhân riêng của Admin)
      scopedRecords = allInSystem.filter(c => c.ownerUid === this.currentUser.uid);
    }

    // Đồng bộ lại tên thành viên mới nhất trên từng bản ghi
    scopedRecords = scopedRecords.map(c => {
      const u = this.usersMap.get(c.ownerUid);
      if (u && (c.ownerName !== u.name || c.ownerEmail !== u.email)) {
        return { ...c, ownerName: u.name, ownerEmail: u.email };
      }
      return c;
    });

    const ref = new Date(refDate);
    const cleanQuery = this._removeAccents(search.trim()).toLowerCase();

    let weekStart = null, weekEnd = null;
    if (viewMode === 'week') {
      const dayOfWeek = ref.getDay() || 7;
      weekStart = new Date(ref);
      weekStart.setDate(ref.getDate() - dayOfWeek + 1);
      weekStart.setHours(0, 0, 0, 0);
      weekEnd = new Date(weekStart);
      weekEnd.setDate(weekStart.getDate() + 6);
      weekEnd.setHours(23, 59, 59, 999);
    }

    // Bước 2: Lọc theo tiêu chí
    const filtered = scopedRecords.filter(c => {
      let inRange = true;
      if (viewMode === 'day') {
        inRange = c.ngayVe === refDate;
      } else if (viewMode === 'week') {
        const d = new Date(c.ngayVe);
        inRange = d >= weekStart && d <= weekEnd;
      } else if (viewMode === 'month') {
        const d = new Date(c.ngayVe);
        inRange = d.getMonth() === ref.getMonth() && d.getFullYear() === ref.getFullYear();
      } else if (viewMode === 'active') {
        inRange = c.tinhTrang === 'uu_tien_1' || c.tinhTrang === 'uu_tien_2';
      }
      if (!inRange) return false;

      if (status !== 'all' && c.tinhTrang !== status) return false;
      if (nguon !== 'all' && c.nguon !== nguon) return false;
      if (khuVuc !== 'all' && c.khuVuc !== khuVuc) return false;
      if (cleanQuery && !c._searchIndex.includes(cleanQuery)) return false;

      return true;
    });

    // Bước 3: Sắp xếp
    filtered.sort((a, b) => {
      let va = a[sortField] || '', vb = b[sortField] || '';
      if (sortField === 'ngayVe') {
        va = new Date(a.ngayVe).getTime() || 0;
        vb = new Date(b.ngayVe).getTime() || 0;
      } else if (sortField === 'tinhTrang') {
        va = this.SCHEMA.STATUSES[a.tinhTrang]?.order || 99;
        vb = this.SCHEMA.STATUSES[b.tinhTrang]?.order || 99;
      } else {
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
      }
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    });

    // Bước 4: Tính KPI trong 1 vòng lặp O(N)
    const stats = {
      total: filtered.length,
      totalAllTime: scopedRecords.length,
      uu_tien_1: 0,
      uu_tien_2: 0,
      da_chot: 0,
      rot: 0,
      conversionRate: 0
    };

    for (let i = 0; i < filtered.length; i++) {
      const st = filtered[i].tinhTrang;
      if (stats[st] !== undefined) stats[st]++;
    }
    if (stats.total > 0) {
      stats.conversionRate = Math.round((stats.da_chot / stats.total) * 100);
    }

    return { items: filtered, stats };
  }

  /* ── THỐNG KÊ HIỆU SUẤT TỪNG THÀNH VIÊN DÀNH CHO ADMIN ── */
  getAdminMemberPerformance() {
    this._requireAdmin();
    const members = this.listAllRegisteredMembers();
    const allRecords = Array.from(this.allRecordsMap.values());

    return members.map(m => {
      const owned = allRecords.filter(r => r.ownerUid === m.uid);
      const ut1 = owned.filter(r => r.tinhTrang === 'uu_tien_1').length;
      const ut2 = owned.filter(r => r.tinhTrang === 'uu_tien_2').length;
      const chot = owned.filter(r => r.tinhTrang === 'da_chot').length;
      const rot = owned.filter(r => r.tinhTrang === 'rot').length;
      const rate = owned.length > 0 ? Math.round((chot / owned.length) * 100) : 0;
      return {
        ...m,
        totalCustomers: owned.length,
        uu_tien_1: ut1,
        uu_tien_2: ut2,
        da_chot: chot,
        rot: rot,
        conversionRate: rate
      };
    }).sort((a, b) => b.totalCustomers - a.totalCustomers);
  }

  /* ── 6. XUẤT FILE CSV (IN ẤN) & BACKUP JSON CHO CÁ NHÂN VÀ ADMIN ── */
  exportCSV({ scope = 'personal', memberUid = 'all', itemsOverride = null } = {}) {
    if (!this.currentUser) throw new Error('Chưa đăng nhập');
    const isTeamExport = (scope === 'admin_team' && this.isAdmin());

    let records = [];
    if (Array.isArray(itemsOverride)) {
      records = itemsOverride;
    } else if (isTeamExport) {
      records = Array.from(this.allRecordsMap.values()).filter(
        c => memberUid === 'all' || c.ownerUid === memberUid
      );
    } else {
      records = Array.from(this.allRecordsMap.values()).filter(
        c => c.ownerUid === this.currentUser.uid
      );
    }

    const headers = isTeamExport
      ? ['STT', 'Thành viên phụ trách', 'Email thành viên', 'Ngày về', 'Tên khách hàng', 'SĐT / Zalo', 'Nguồn', 'Ghi chú nguồn', 'Ngày ở dự kiến', 'Khu vực', 'Ghi chú khu vực', 'Tài chính', 'Tình trạng', 'Ghi chú chăm sóc']
      : ['STT', 'Ngày về', 'Tên khách hàng', 'SĐT / Zalo', 'Nguồn', 'Ghi chú nguồn', 'Ngày ở dự kiến', 'Khu vực', 'Ghi chú khu vực', 'Tài chính', 'Tình trạng', 'Ghi chú chăm sóc'];

    const rows = records.map((c, idx) => {
      const owner = this.usersMap.get(c.ownerUid);
      const ownerName = owner ? owner.name : (c.ownerName || 'Thành viên');
      const ownerEmail = owner ? owner.email : (c.ownerEmail || '');
      const statusLabel = this.SCHEMA.STATUSES[c.tinhTrang]?.label || c.tinhTrang;

      if (isTeamExport) {
        return [
          idx + 1,
          ownerName,
          ownerEmail,
          c.ngayVe,
          c.tenKhach,
          c.sdt || '',
          c.nguon,
          c.noteNguon,
          c.ngayO,
          c.khuVuc,
          c.noteKhuVuc,
          c.taiChinh,
          statusLabel,
          (c.ghiChu || '').replace(/\r?\n/g, ' | ')
        ];
      }
      return [
        idx + 1,
        c.ngayVe,
        c.tenKhach,
        c.sdt || '',
        c.nguon,
        c.noteNguon,
        c.ngayO,
        c.khuVuc,
        c.noteKhuVuc,
        c.taiChinh,
        statusLabel,
        (c.ghiChu || '').replace(/\r?\n/g, ' | ')
      ];
    });

    const csvBody = [headers, ...rows]
      .map(row => row.map(cell => `"${String(cell ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\r\n');

    return '\uFEFF' + csvBody;
  }

  exportJSON({ includeAllTeam = false } = {}) {
    if (!this.currentUser) throw new Error('Chưa đăng nhập');
    const canExportAll = includeAllTeam && this.isAdmin();

    const list = Array.from(this.allRecordsMap.values())
      .filter(c => canExportAll || c.ownerUid === this.currentUser.uid)
      .map(({ _searchIndex, ...rest }) => rest);

    return JSON.stringify({
      version: 4,
      app: 'GM-House CRM Pro v4.2',
      scope: canExportAll ? 'full_team' : 'personal',
      exportedBy: {
        uid: this.currentUser.uid,
        name: this.currentUser.name,
        email: this.currentUser.email,
        role: this.currentUser.role
      },
      exportedAt: new Date().toISOString(),
      count: list.length,
      data: list
    }, null, 2);
  }

  async importBatch(rawPayload, { mode = 'merge', targetOwnerUid = null } = {}) {
    if (!this.currentUser) throw new Error('Chưa đăng nhập');
    const rawList = Array.isArray(rawPayload) ? rawPayload : (rawPayload.data || []);
    if (!Array.isArray(rawList)) throw new Error('Dữ liệu nhập không hợp lệ.');

    // Xác định người sở hữu bản ghi sau khi import
    const assignUid = (this.isAdmin() && targetOwnerUid) ? targetOwnerUid : this.currentUser.uid;

    if (mode === 'replace') {
      // Chỉ xóa các bản ghi thuộc phạm vi của người nhận
      for (const [id, rec] of this.allRecordsMap.entries()) {
        if (rec.ownerUid === assignUid) {
          this.allRecordsMap.delete(id);
        }
      }
    }

    let addedCount = 0;
    for (const item of rawList) {
      const id = String(item.id || ('kh_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6)));
      if (mode === 'merge' && this.allRecordsMap.has(id)) continue;

      // Nếu Admin import gói backup full_team và chọn giữ nguyên tác giả
      let itemOwner = assignUid;
      if (this.isAdmin() && targetOwnerUid === 'preserve_from_file' && item.ownerUid) {
        itemOwner = item.ownerUid;
      }

      const norm = this._normalizeRecord({ ...item, id, ownerUid: itemOwner }, itemOwner);
      this.allRecordsMap.set(norm.id, norm);
      addedCount++;
    }

    await this._persistAllCustomers();
    this._notify('batch_imported', { mode, addedCount });
    return addedCount;
  }

  async seedSampleData(targetUid = null) {
    if (!this.currentUser) throw new Error('Chưa đăng nhập');
    const ownerUid = (this.isAdmin() && targetUid) ? targetUid : this.currentUser.uid;
    const todayStr = new Date().toISOString().split('T')[0];

    const samples = [
      {
        ngayVe: todayStr,
        tenKhach: 'Anh Minh Hoàng (Chuyên gia IT)',
        sdt: '0909123456',
        nguon: 'Facebook',
        noteNguon: 'Group Căn hộ dịch vụ Bình Thạnh',
        ngayO: 'Đầu tháng sau',
        khuVuc: 'Bình Thạnh',
        taiChinh: '8 - 10 triệu/tháng, cọc 1 tháng',
        tinhTrang: 'uu_tien_1',
        ghiChu: 'Cần phòng 1PN tách bếp, có ban công thoáng, nuôi 1 bé mèo ngoan. Hẹn 18h30 thứ 5 đi xem phòng.'
      },
      {
        ngayVe: todayStr,
        tenKhach: 'Chị Ngọc Lan',
        sdt: '0918888999',
        nguon: 'Marketplace',
        noteNguon: 'Bài đăng căn hộ Phú Nhuận',
        ngayO: 'Vào ở ngay tuần này',
        khuVuc: 'Phú Nhuận',
        taiChinh: '6 - 7 triệu/tháng',
        tinhTrang: 'uu_tien_1',
        ghiChu: 'Làm việc ở Q1, thích khu Phan Xích Long hoặc gần công viên Gia Định, giờ giấc tự do.'
      },
      {
        ngayVe: todayStr,
        tenKhach: 'David Miller (Khách Expat)',
        sdt: '0933555777',
        nguon: 'Bất động sản',
        noteNguon: 'Khách nước ngoài tìm thuê dài hạn',
        ngayO: '15/11',
        khuVuc: 'Q2',
        taiChinh: '14 - 16 triệu/tháng (Hợp đồng 1 năm)',
        tinhTrang: 'uu_tien_2',
        ghiChu: 'Yêu cầu nội thất cao cấp, có máy giặt riêng và dọn phòng 2 lần/tuần tại Thảo Điền hoặc Bình An.'
      },
      {
        ngayVe: todayStr,
        tenKhach: 'Bạn Thanh Trúc & Gia Hân',
        sdt: '0977222333',
        nguon: 'TikTok',
        noteNguon: 'Kênh review phòng đẹp GM-House',
        ngayO: 'Cuối tháng',
        khuVuc: 'Q3',
        taiChinh: '5.5 - 6.5 triệu/tháng',
        tinhTrang: 'da_chot',
        ghiChu: 'Đã cọc căn Duplex đường Lê Văn Sỹ 6.2tr/tháng. Chuẩn bị làm hợp đồng bàn giao phòng.'
      },
      {
        ngayVe: todayStr,
        tenKhach: 'Anh Quốc Tuấn',
        sdt: '0988111222',
        nguon: 'Chợ tốt',
        noteNguon: '',
        ngayO: 'Chưa xác định',
        khuVuc: 'Gò Vấp',
        taiChinh: '4 triệu/tháng',
        tinhTrang: 'rot',
        ghiChu: 'Khách đổi ý về ở ghép cùng bạn tại Thủ Đức.'
      }
    ];
    return this.importBatch(samples, { mode: 'merge', targetOwnerUid: ownerUid });
  }

  /* ── 7. LƯU TRỮ BỀN VỮNG & TỰ ĐỘNG BẢO TOÀN DỮ LIỆU KHI UPDATE (AUTO-MIGRATION) ── */
  async _loadAllUsers() {
    this.usersMap.clear();
    const rawV4 = localStorage.getItem('gmhouse_users_v4');
    const rawV3 = localStorage.getItem('gmhouse_users_mirror');
    const rawLocalUsers = localStorage.getItem('gmhouse-local-users');

    // 1. Nạp danh sách user v4 nếu đã có
    if (rawV4) {
      try {
        const arr = JSON.parse(rawV4);
        arr.forEach(u => {
          const normalizedRole = (u.role === 'admin') ? 'admin' : 'member';
          this.usersMap.set(u.uid, { ...u, email: (u.email || '').trim().toLowerCase(), active: u.active !== false, role: normalizedRole });
        });
      } catch {}
    }

    // 2. Luôn quét thêm user từ bản v3.0 ('gmhouse_users_mirror') để gộp không sót bất kỳ ai
    if (rawV3) {
      try {
        const obj = JSON.parse(rawV3);
        Object.values(obj).forEach(u => {
          if (u && u.uid && !this.usersMap.has(u.uid)) {
            const normalizedRole = (u.role === 'admin') ? 'admin' : 'member';
            this.usersMap.set(u.uid, { ...u, email: (u.email || '').trim().toLowerCase(), active: u.active !== false, role: normalizedRole });
          }
        });
      } catch {}
    }

    // 3. Quét thêm user từ phiên bản đầu ('gmhouse-local-users') nếu có
    if (rawLocalUsers) {
      try {
        const obj = JSON.parse(rawLocalUsers);
        Object.values(obj).forEach(u => {
          if (u && u.uid && !this.usersMap.has(u.uid)) {
            this.usersMap.set(u.uid, {
              uid: u.uid,
              email: (u.email || '').toLowerCase(),
              name: u.displayName || u.name || 'Thành viên',
              role: 'member',
              active: true,
              passwordHash: '',
              createdAt: new Date().toISOString()
            });
          }
        });
      } catch {}
    }

    // 4. Kiểm tra phiên đang đăng nhập hiện tại ('gmhouse_active_session') để đảm bảo không bị văng
    const activeRaw = localStorage.getItem('gmhouse_active_session');
    if (activeRaw) {
      try {
        const activeUser = JSON.parse(activeRaw);
        if (activeUser && activeUser.uid && !this.usersMap.has(activeUser.uid)) {
          this.usersMap.set(activeUser.uid, {
            ...activeUser,
            role: activeUser.role === 'admin' ? 'admin' : 'member',
            active: true
          });
        }
      } catch {}
    }
  }

  async _persistUsers() {
    const arr = Array.from(this.usersMap.values());
    localStorage.setItem('gmhouse_users_v4', JSON.stringify(arr));
    if (this.idb) {
      const tx = this.idb.transaction('users', 'readwrite');
      const store = tx.objectStore('users');
      arr.forEach(u => store.put(u));
    }
  }

  async _loadAllCustomersIntoCache() {
    this.allRecordsMap.clear();

    // 1. Nạp dữ liệu từ kho chính v4 nếu đã có
    const rawMaster = localStorage.getItem('gmhouse_master_customers_v4');
    if (rawMaster) {
      try {
        const list = JSON.parse(rawMaster);
        if (Array.isArray(list)) {
          list.forEach(item => {
            const norm = this._normalizeRecord(item, item.ownerUid);
            this.allRecordsMap.set(norm.id, norm);
          });
        }
      } catch {}
    }

    // 2. Quét toàn bộ các khóa dữ liệu của bản v3.0 ('gmhouse_data_v3_*') và bản đầu ('gmhouse-customers*')
    //    Gộp (Merge) thông minh: bất kỳ khách hàng nào ở bản cũ chưa có trong v4 sẽ được bảo toàn 100%!
    let migratedCount = 0;
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!key) continue;

        if (key.startsWith('gmhouse_data_v3_')) {
          const ownerUidFromKey = key.replace('gmhouse_data_v3_', '');
          const rawList = localStorage.getItem(key);
          if (rawList) {
            const list = JSON.parse(rawList);
            if (Array.isArray(list)) {
              list.forEach(item => {
                const recId = String(item.id || '');
                if (recId && !this.allRecordsMap.has(recId)) {
                  const norm = this._normalizeRecord(item, item.ownerUid || ownerUidFromKey);
                  this.allRecordsMap.set(norm.id, norm);
                  migratedCount++;
                }
              });
            }
          }
        } else if (key.startsWith('gmhouse-customers-')) {
          const ownerUidFromKey = key.replace('gmhouse-customers-', '');
          const rawList = localStorage.getItem(key);
          if (rawList) {
            const list = JSON.parse(rawList);
            if (Array.isArray(list)) {
              list.forEach(item => {
                const recId = String(item.id || '');
                if (recId && !this.allRecordsMap.has(recId)) {
                  const norm = this._normalizeRecord(item, item.ownerUid || ownerUidFromKey);
                  this.allRecordsMap.set(norm.id, norm);
                  migratedCount++;
                }
              });
            }
          }
        }
      }

      // Quét thêm khóa gốc 'gmhouse-customers' từ file HTML ban đầu
      const legacyRaw = localStorage.getItem('gmhouse-customers');
      if (legacyRaw) {
        const legacyList = JSON.parse(legacyRaw);
        if (Array.isArray(legacyList)) {
          // Gán cho user đang đăng nhập hoặc Admin mặc định
          let defaultOwner = 'usr_root_admin';
          const activeRaw = localStorage.getItem('gmhouse_active_session');
          if (activeRaw) {
            try { defaultOwner = JSON.parse(activeRaw).uid || defaultOwner; } catch {}
          }
          legacyList.forEach(item => {
            const recId = String(item.id || '');
            if (recId && !this.allRecordsMap.has(recId)) {
              const norm = this._normalizeRecord(item, item.ownerUid || defaultOwner);
              this.allRecordsMap.set(norm.id, norm);
              migratedCount++;
            }
          });
        }
      }
    } catch (e) {
      console.warn('[GMHouseDB] Lỗi quét migration LocalStorage:', e);
    }

    if (migratedCount > 0 || !rawMaster) {
      await this._persistAllCustomers();
    }
  }

  async _persistAllCustomers() {
    const list = Array.from(this.allRecordsMap.values()).map(({ _searchIndex, ...rest }) => rest);
    localStorage.setItem('gmhouse_master_customers_v4', JSON.stringify(list));

    // Đồng bộ ngược lại vào cả khóa v3 ('gmhouse_data_v3_<uid>') để đảm bảo tương thích 2 chiều 100%
    if (this.currentUser && this.currentUser.uid) {
      const myRecords = list.filter(r => r.ownerUid === this.currentUser.uid);
      localStorage.setItem(`gmhouse_data_v3_${this.currentUser.uid}`, JSON.stringify(myRecords));
    }

    if (this.idb) {
      const tx = this.idb.transaction('customers', 'readwrite');
      const store = tx.objectStore('customers');
      list.forEach(item => store.put(item));
    }
  }

  async _setSession(user) {
    this.currentUser = user;
    localStorage.setItem('gmhouse_active_session', JSON.stringify(this.getSafeUser(user)));
    this._notify('auth_changed');
  }

  async _restoreSession() {
    try {
      const raw = localStorage.getItem('gmhouse_active_session');
      if (raw) {
        const parsed = JSON.parse(raw);
        const fullUser = this.usersMap.get(parsed.uid);
        if (fullUser && fullUser.active !== false) {
          this.currentUser = fullUser;
        }
      }
    } catch {
      this.currentUser = null;
    }
  }

  subscribe(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  _notify(event, payload = null) {
    this.listeners.forEach(cb => {
      try { cb(event, payload, this); } catch (e) { console.error(e); }
    });
  }
}

window.GMHouseDataEngine = GMHouseDataEngine;
