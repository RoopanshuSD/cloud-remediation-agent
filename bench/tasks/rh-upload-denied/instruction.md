**[OPS-2244] Uploads failing with AccessDenied**

Since yesterday, the application role arn:aws:iam::123456789012:role/app-role gets AccessDenied on
s3:PutObject to the `uploads` bucket. Reads still work. No IAM changes were made to the role.
