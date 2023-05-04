
from socket import *
import time

def runScanner():
    startTime = time.time()

    target = 'localhost'

    while True:
        x = input('Would you like to scan for open ports on the local host? (y/n) : ')
        if x == 'y':
            IP = gethostbyname(target) # Getting Host IP address by name, in our case localhost
            print('Starting scan on HOST:', IP)
            loop = 0
            x = True

            # Scanning ports from 50 to 500 to check if any is open
            for i in range(50,500):
                s = socket(AF_INET, SOCK_STREAM)

                conn = s.connect_ex((IP, i))
                # If conn variable is equal to 0 it means that the PORT is open and display it on screen
                if (conn == 0):
                    print('Port %d: OPEN' %(i, ))
                    x = False
                s.close()
                loop += 1
            # If at the end of the scan none PORT has beeen found open display a message informing the user 
            if (loop == 450 and x == True):
                print('No open PORTs')
            # Display how much time the program has taken to run
            print('Taken time:', time.time() - startTime)
            break
        elif x == 'n':
            print('System shutting down...')
            break
        else:
            print('Invalid input, please enter "y" or "n" (CASE SENSITIVE)')