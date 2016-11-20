num_fail = 0
num_success = 0
num_total = 0

f = open("multitestlog.txt", "r")
for l in f:
	if "OK ] TestEnv_Congestion2.TestCongestion2" in l:
		num_success += 1
	elif "FAILED  ] TestEnv_Congestion2.TestCongestion2" in l:
		num_fail += 1

assert(num_fail % 2 == 0)
num_fail //= 2
num_total = num_fail + num_success

fw = open("multitestresult.txt", "w")
fw.write("TOTAL NUMBER OF TESTS:   %d\n" % num_total)
fw.write("TOTAL NUMBER OF SUCCESS: %d\n" % num_success)
fw.write("TOTAL NUMBER OF FAILS:   %d\n" % num_fail)
fw.write("FAILURE RATE:            %.3f%%\n" % ((float(num_fail) / num_total) * 100))

f.close()
fw.close()
