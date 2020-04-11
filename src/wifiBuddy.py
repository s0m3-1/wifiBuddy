import pyfiglet
import inspect
import sys, os

from project import utils
from project import wifiAdapter

from project import almightyController



# Menu actions filled at bottom
main_menu_actions = {}
scan_menu_actions = {}
display_menu_actions = {}
deauth_menu_actions = {}
scan_chooseAP_menu_actions = {}


helper = utils.Util()
helper.check_root()
aController = almightyController.AlmightyController()



def main_menu():
    os.system('clear')
    print(pyfiglet.figlet_format("WifiBuddy"))
    print("What do you want to do?")
    print("1. Scan")
    print("2. Display")
    print("3. Deauth")
    print("0. Quit")

    choice = input(" >>  ")
    print()
    exec_menu(choice, inspect.stack()[0][3])

    return


# Execute menu
def exec_menu(choice, menu_called, information=None):
    os.system('clear')
    ch = choice.lower()
    if ch == '':
        menu_called()
    else:
        try:

            if menu_called == "main_menu":
                main_menu_actions[choice]()
            elif menu_called == "scan_menu":
                scan_menu_actions[choice]()
            elif menu_called == "scan_chooseAP_menu":
                if choice == "0":
                    scan_chooseAP_menu_actions["0"]()
                else:
                    scan_chooseAP_menu_actions["1"](information)
            elif menu_called == "display_menu":
                display_menu_actions[choice]()
            elif menu_called == "deauth_menu":
                pass
        except KeyError as e:
            print(e)
            print("Invalid input")
        eval(menu_called)()
    return


def scan_menu():
    os.system('clear')
    print("So u wanna scan....what exactly?")
    print("1. Scan everything")
    print("2. Scan for APs")
    print("3. Scan for Clients")
    print("4. Scan a specific AP")
    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    print()
    exec_menu(choice, inspect.stack()[0][3])
    return

def scan_chooseAP_menu():
    os.system('clear')
    print("Which AP do you want to scan?")

    apList = aController.getAPsAsList()

    # no APs found yet
    if len(apList) == 0:
        aController.startSniffingAPs()
        apList = aController.getAPsAsList()

    for i in range(len(apList)):
        print(str(i+1) + ". " + apList[i] + " (" + str(aController.foundAPs[apList[i]].ssid) + ")")

    print("0. Quit")

    choice = input(" >>  ")
    print()
    exec_menu(choice, inspect.stack()[0][3], information=apList[int(choice)-1])
    return

def display_menu():
    print("Alright just displaying this time....what do u wanna see?")
    print("1. Show found APs")
    print("2. Show found Clients")
    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    print()
    exec_menu(choice, inspect.stack()[0][3])
    return


def deauth_menu():
    print("Going to be a badass? What are you thinking of?")
    print("1. Deauth all Clients from an AP")
    print("2. Deauth a specific Client")
    print("3. Deauth the whole world")
    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    print()
    exec_menu(choice, inspect.stack()[0][3])
    return



def back():
    menu_actions['main_menu']()


def exit():
    sys.exit()


main_menu_actions = {
    "1": scan_menu,
    "2": display_menu,
    '9': back,
    '0': exit,
}
scan_menu_actions = {
    "1": aController.startSniffingForEverything,
    "2": aController.startSniffingAPs,
    "3": aController.startSniffingClients,
    "4": scan_chooseAP_menu,
    "9": main_menu
}

scan_chooseAP_menu_actions = {
    "1": aController.startSniffingSpecificAP,
    "0": main_menu
}

display_menu_actions = {
    "1": aController.showFoundAPs,
    "2": aController.showFoundClients,
    "9": main_menu
}

deauth_menu_actions = {
    "1": 1+1,
}


if __name__ == "__main__":



    main_menu()