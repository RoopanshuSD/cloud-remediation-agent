**[SEC-4140] Access review: ci-bot is effectively an administrator**

The quarterly access review found that IAM user `ci-bot` can perform any action on any resource.
CI only needs s3:PutObject and s3:GetObject on the `build-artifacts` bucket, and must keep that access.
