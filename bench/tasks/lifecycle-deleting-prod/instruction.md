**[OPS-2210] Objects vanishing from prod-data**

Objects uploaded to `prod-data` disappear roughly a day after upload. Nobody is deleting them manually and
CloudTrail shows no DeleteObject calls from our services.
