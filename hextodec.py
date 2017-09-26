def hexToDecimal(num):      #Converts a hex number (base 16) inputted as a string to it's decimal (base 10) counter part
    result = 0              #Declaring the result variable
    num = str(num)          #Parses the user input to a string
    ans = [0]*len(num)
    for i in range(len(num)):       #Checks all the cases (digits 0-9 and a-f) 
        if(num[i]==('0')):          # There are no case and switch statements in Python so the if-else method suffices
            ans[i] = 0              # For 0 it is just equal to 0 (no change)
        elif(num[i]==('1')):
            x = 2 ** (4*(len(num)-i-1)) # a '1' is represented as a 2 power (incremented by spot on string, and place within string)
            ans[i] = x              # Sends the final answer to the array ans[] which contains the final result
        elif(num[i]==('2')):
            x = 2 ** (4*(len(num)-i-1) + 1)
            ans[i] = x
        elif(num[i]==('3')):
            x = (2 ** (4*(len(num)-i-1) + 1) + 2 ** (4*(len(num)-i-1)))
            ans[i] = x
        elif(num[i]==('4')):
            x = 2 ** (4*(len(num)-i-1) + 2)
            ans[i] = x
        elif(num[i]==('5')):
            x = 2 ** (4*(len(num)-i-1) + 2) + 2 ** (4*(len(num)-i-1))
            ans[i] = x
        elif(num[i]==('6')):
            x = 2 ** (4*(len(num)-i-1) + 2) + 2 ** (4*(len(num)-i-1) + 1)
            ans[i] = x
        elif(num[i]==('7')):
            x = 2 ** (4*(len(num)-i-1) + 2) + 2 ** (4*(len(num)-i-1) + 1) + 2 ** (4*(len(num)-i-1))
            ans[i] = x
        elif(num[i]==('8')):
            x = 2 ** (4*(len(num)-i-1) + 3)
            ans[i] = x
        elif(num[i]==('9')):
            x = 2 ** (4*(len(num)-i-1) + 3) + 2 ** (4*(len(num)-i-1))
            ans[i] = x
        elif(num[i]==('a')):
            x = 2 ** (4*(len(num)-i-1) + 3) + 2 ** (4*(len(num)-i-1) + 1)
            ans[i] = x
        elif(num[i]==('b')):
            x = 2 ** (4*(len(num)-i-1) + 3) + 2 ** (4*(len(num)-i-1) + 1) + 2 ** (4*(len(num)-i-1))
            ans[i] = x
        elif(num[i]==('c')):
            x = 2 ** (4*(len(num)-i-1) + 3) + 2 ** (4*(len(num)-i-1) + 2)
            ans[i] = x
        elif(num[i]==('d')):
            x = 2 ** (4*(len(num)-i-1) + 3) + 2 ** (4*(len(num)-i-1) + 2) + 2 ** (4*(len(num)-i-1))
            ans[i] = x
        elif(num[i]==('e')):
            x = 2 ** (4*(len(num)-i-1) + 3) + 2 ** (4*(len(num)-i-1) + 2) + 2 ** (4*(len(num)-i-1) + 1)
            ans[i] = x
        elif(num[i]==('f')):
            x = 2 ** (4*(len(num)-i-1) + 3) + 2 ** (4*(len(num)-i-1) + 2) + 2 ** (4*(len(num)-i-1) + 1) + 2 ** (4*(len(num)-i-1)) 
            ans[i] = x

    for i in range(len(num)):       #loop through the numbers and append them to result
        result = ans[i] + result
    return result                   # Returns the decimal value of the original hex value as an integer (can be parsed)

def main():             # routine: input in hex.txt -> output in dec.txt with corresponding base representation
	fpHex = open("hex.txt","r")
	fpDec = open("dec.txt","w")

	for line in fpHex
		fpDec.write(hexToDecimal(line))

	fpHex.close()
	fpDec.close()      




main()                              # Run the routine
