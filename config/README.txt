# Config files for scan

These config files define the routers under test for the scanGns3Infra script.
We had issues with running all the routers under test at the same test.
Sometimes some packets would be dropped or delayed significantly.
Thus, we split the main config.yml into multiple batches.
