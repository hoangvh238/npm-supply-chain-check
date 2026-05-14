# 🚨 SupplyChain-IOC-Scanner

Script kiểm tra nhanh dấu hiệu nhiễm malware liên quan đến các vụ npm supply chain attack gần đây như TanStack / Mini Shai-Hulud.

## Script sẽ kiểm tra gì

• `gh-token-monitor` persistence
• `router_init` / `router_runtime` malware artifacts
• Claude AI hooks
• VSCode task persistence
• WSL / systemd services
• cron jobs đáng ngờ
• scheduled tasks
• registry autorun
• startup folder
• suspicious background processes

## Vì sao script này tồn tại

Các vụ attack gần đây lợi dụng:

• `npm install`
• `prepare` / `postinstall` hooks
• GitHub Actions OIDC
• dependency auto update qua dấu `^`

để đánh cắp:

* GitHub token
* AWS credentials
* SSH key
* `.env`
* CI/CD secrets

Chi tiết vụ việc:
[Snyk TanStack incident report](https://snyk.io/blog/tanstack-npm-packages-compromised/?utm_source=chatgpt.com)

---

# Cách dùng

Chạy file:

```bat id="w3d1n9"
npm-supply-chain-check.bat
```

Script sẽ:

* hiển thị kết quả trên terminal
* export log ra file:

```txt id="n2v7y8"
security-check-result.txt
```

---

# Nếu phát hiện dấu hiệu bất thường

Khuyến nghị:

1. Rotate GitHub token / PAT
2. Rotate AWS/API secrets
3. Kiểm tra SSH keys
4. Audit CI/CD credentials
5. Xóa persistence mechanisms
6. Scan antivirus toàn bộ máy
7. Review lại các package npm vừa cài gần đây

---

# Lưu ý

Đây là IOC scanner hỗ trợ kiểm tra nhanh.

Không đảm bảo phát hiện toàn bộ malware hoặc persistence mechanism.

Nếu nghi ngờ môi trường đã bị compromise:
👉 nên audit và rotate toàn bộ secrets.
