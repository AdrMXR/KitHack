from colorama import Fore, init

def menu():
	print("{}------------------------------------------------------------------------------------- ".format(Fore.LIGHTRED_EX))
	print("||                                        {}MENU{}                                       ||".format(Fore.WHITE, Fore.LIGHTRED_EX))
	print("||-----------------------------------------------------------------------------------||")
	print("||                                         |                                         ||")
	print("||          [01] {}Android{}                   |       [07] {}Spoofing{}                     ||".format(Fore.WHITE, Fore.RED, Fore.WHITE, Fore.RED))
	print("||                                         |                                         ||")
	print("||          [02] {}Windows{}                   |       [08] {}Information Gathering{}        ||".format(Fore.WHITE, Fore.RED, Fore.WHITE, Fore.RED))
	print("||                                         |                                         ||")
	print("||          [03] {}Phishing{}                  |       [09] {}Others{}                       ||".format(Fore.WHITE, Fore.RED, Fore.WHITE, Fore.RED))
	print("||                                         |                                         ||")
	print("||          [04] {}Wifi Attacks{}              |       [10] {}Backdoors with msfvenom{}      ||".format(Fore.WHITE, Fore.RED, Fore.WHITE, Fore.RED))
	print("||                                         |                                         ||")
	print("||          [05] {}Passwords Attacks{}         |       [11] {}Help{}                         ||".format(Fore.WHITE, Fore.RED, Fore.WHITE, Fore.RED))
	print("||                                         |                                         ||")
	print("||          [06] {}Web Attacks{}               |       [12] {}Exit{}                         ||".format(Fore.WHITE, Fore.RED, Fore.WHITE, Fore.RED))
	print("-------------------------------------------------------------------------------------")

menu()