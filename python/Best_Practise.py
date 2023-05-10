import os

def delete_file(filename):
    os.remove(filename)

if __name__ == '__main__':
    file_name = input('Enter the name of the file you want to delete: ')
    delete_file(file_name)