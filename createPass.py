import os


def createPass():

    i = 55555
    while i <= 99999:
        with open("./passfile.txt", 'a') as f1:
            f1.write(str(i) + os.linesep)
        i+=1
    i = 55554
    while i > 10000:
        with open("./passfile.txt", 'a') as f1:
            f1.write(str(i) + os.linesep)
        i-=1

createPass()