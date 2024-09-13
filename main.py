

import base64


def main():
    my_cool_input = input('Enter something fun')
    eval(my_cool_input)

def another_function():
    pass

def code_execution(request):
    "lifted from docs hopefully triggers a problem"
    if request.method == 'POST':
        first_name = base64.decodestring(request.POST.get('first_name', ''))
        #BAD -- Allow user to define code to be run.
        exec("setname('%s')" % first_name)
        
if __name__ == '__main__':
    main()