**[SEC-4133] Scanner finding: SSH exposed to the internet**

External attack-surface scan flagged port 22 on instances in security group `app-sg` as open to the internet.
`app-sg` fronts our customer-facing HTTPS service.
