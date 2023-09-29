connected_users = {'1': 'CPfbfJsQlN1BjFjcAAAJ', '3': 'fd3XTX_asKY7KqllAAAL'}
session_id = 'CPfbfJsQlN1BjFjcAAAJ'
# user_id = input("Raqam kiriting: ")
# if user_id not in connected_users.keys():
#     # Записываем session_id в словарь
#     connected_users[user_id] = session_id
#     print(connected_users)
# else:
#     print("Such a user exists")

for user_id, sid in list(connected_users.items()):
    print(user_id, sid)
    if sid == session_id:
        print(sid)
        del connected_users[user_id]
        print(connected_users)
        break
    print("User o'chirildi")
    print(connected_users)