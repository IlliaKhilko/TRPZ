import abc
import socket
import threading
from enum import Enum
from project.factory import SQLiteDatabaseFactory

class Handler(abc.ABC):
    @abc.abstractmethod
    def handle(self, server, client_socket, current_user, command_args):
        pass

class RegisterHandler(Handler):
    def handle(self, server, client_socket, current_user, command_args):
        if len(command_args) == 2:
            username, password = command_args
            try:
                with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        client_socket.send('Username is already taken. Please choose another one.'.encode('utf-8'))
                    else:
                        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                        client_socket.send('Registration successful!'.encode('utf-8'))
            except Exception as e:
                print(f'Error registering user: {e}')
                client_socket.send('Error during registration. Please try again.'.encode('utf-8'))
        else:
            client_socket.send('Invalid registration format. Usage: REGISTER username password'.encode('utf-8'))
class LoginHandler(Handler):
    def handle(self, server, client_socket, current_user, command_args):
        if len(command_args) == 2:
            username, password = command_args
            try:
                with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
                    user = cursor.fetchone()
                    if user:
                        client_socket.send('Login successful!'.encode('utf-8'))
                        server.current_state = ServerState.LOGGED_IN
                        return user
                    else:
                        client_socket.send('Invalid username or password.'.encode('utf-8'))
            except Exception as e:
                print(f'Error during login: {e}')
                client_socket.send('Error during login. Please try again.'.encode('utf-8'))
        else:
            client_socket.send('Invalid login format. Usage: LOGIN username password'.encode('utf-8'))

        return None
class LoginRegisterCommandHandler(Handler):
    def handle(self, server, client_socket, current_user, command, command_args):
        if command == 'REGISTER':
            RegisterHandler().handle(server, client_socket, current_user, command_args)
        elif command == 'LOGIN':
            return LoginHandler().handle(server, client_socket, current_user, command_args)
        else:
            client_socket.send('Invalid command. Please enter a valid command.'.encode('utf-8'))
class ServerState(Enum):
    NOT_LOGGED_IN = 1
    LOGGED_IN = 2
class Server:
    def __init__(self, host='127.0.0.1', port=5559):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.current_state = ServerState.NOT_LOGGED_IN
        self.register_handler = RegisterHandler()
        self.login_handler = LoginHandler()
        self.login_register_handler = LoginRegisterCommandHandler()
        self.client_states = {}
        print(f'Server is listening on {self.host}:{self.port}')
    def start_server(self):
        while True:
            client, address = self.server.accept()
            print(f'Accepted connection from {address}')
            client_handler = threading.Thread(target=self.handle_client, args=(client,))
            client_handler.start()
    def handle_client(self, client_socket):
        self.client_states[client_socket] = ServerState.NOT_LOGGED_IN
        current_user = None
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            decoded_data = data.decode('utf-8')
            print(f'Received from client: {decoded_data}')

            if self.client_states[client_socket] == ServerState.NOT_LOGGED_IN:
                if decoded_data.startswith(('REGISTER', 'LOGIN')):
                    command, *command_args = decoded_data.split()
                    current_user = self.login_register_handler.handle(
                        self, client_socket, current_user, command, command_args
                    )
                    if current_user and command == 'LOGIN':
                        self.client_states[client_socket] = ServerState.LOGGED_IN
                else:
                    client_socket.send('Please log in first.'.encode('utf-8'))
            elif self.client_states[client_socket] == ServerState.LOGGED_IN:
                self.process_user_command(client_socket, current_user, decoded_data.split())

        del self.client_states[client_socket]
        client_socket.close()

    def process_user_command(self, client_socket, current_user, command_args):
        if command_args[0] == 'CREATE_GROUP':
            self.create_group(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'JOIN_GROUP':
            self.join_group(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'LIST_GROUPS':
            self.list_groups(client_socket)
        elif command_args[0] == 'ADD_ITEM':
            self.add_item(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'LIST_ITEMS_IN_GROUP':
            self.list_items_in_group(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'MARK_PURCHASE':
            self.mark_purchase(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'ASSIGN_ITEM':
            self.assign_item(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'ADD_FRIEND':
            self.add_friend(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'USER_INFO':
            self.user_info(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'CREATE_WISHLIST':
            self.create_wishlist(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'MANAGE_WISHLIST_VISIBILITY':
            self.manage_wishlist_visibility(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'VIEW_WISHLIST':
            self.view_wishlist(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'ADD_TO_WISHLIST':
            self.add_to_wishlist(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'LIST_WISHLISTS':
            self.list_wishlists(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'LEAVE_GROUP':
            self.leave_group(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'REMOVE_ITEM':
            self.remove_item(client_socket, current_user, command_args[1:])
        elif command_args[0] == 'GROUP_MEMBERS':
            self.group_members(client_socket, current_user, command_args[1:])
        else:
            client_socket.send('Invalid command. Please enter a valid command.'.encode('utf-8'))


    def list_wishlists(self, client_socket, user, args):
        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                cursor.execute(
                    'SELECT w.wishlist_id, w.wishlist_name FROM wishlists w LEFT JOIN wishlist_visibility wv ON w.wishlist_id=wv.wishlist_id WHERE w.user_id=? OR wv.friend_id=?',
                    (user[0], user[0]))
                wishlists = cursor.fetchall()

                if wishlists:
                    wishlists_info = '\n'.join([f'{wishlist[0]}. {wishlist[1]}' for wishlist in wishlists])
                    client_socket.send(f'Available wishlists:\n{wishlists_info}'.encode('utf-8'))
                else:
                    client_socket.send('No wishlists available.'.encode('utf-8'))
        except Exception as e:
            print(f'Error listing wishlists: {e}')
            client_socket.send('Error listing wishlists. Please try again.'.encode('utf-8'))


    def add_to_wishlist(self, client_socket, user, args):
        if len(args) < 3:
            client_socket.send(
                'Invalid command format. Usage: ADD_TO_WISHLIST wishlist_id item_name estimated_price'.encode(
                    'utf-8'))
            return

        wishlist_id, item_name, estimated_price = args[0], args[1], args[2]
        try:
            wishlist_id = int(wishlist_id)
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                cursor.execute('SELECT user_id FROM wishlists WHERE wishlist_id=?', (wishlist_id,))
                wishlist_owner = cursor.fetchone()

                if wishlist_owner and wishlist_owner[0] == user[0]:
                    cursor.execute(
                        'INSERT INTO wishlist_items (wishlist_id, item_name, estimated_price) VALUES (?, ?, ?)',
                        (wishlist_id, item_name, estimated_price))
                    client_socket.send(
                        f'Item "{item_name}" added to wishlist {wishlist_id} successfully!'.encode('utf-8'))
                else:
                    client_socket.send(f'You do not have permission to add items to this wishlist.'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid wishlist_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error adding item to wishlist: {e}')
            client_socket.send('Error adding item to wishlist. Please try again.'.encode('utf-8'))

    def view_wishlist(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: VIEW_WISHLIST wishlist_id'.encode('utf-8'))
            return

        wishlist_id = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                wishlist_id = int(wishlist_id)
                cursor.execute('SELECT user_id FROM wishlists WHERE wishlist_id=?', (wishlist_id,))
                wishlist_owner = cursor.fetchone()
                cursor.execute('SELECT * FROM wishlist_visibility WHERE wishlist_id=? AND friend_id=?',
                               (wishlist_id, user[0]))
                has_visibility = cursor.fetchone()

                if wishlist_owner and (wishlist_owner[0] == user[0] or has_visibility):
                    cursor.execute('SELECT item_name, estimated_price FROM wishlist_items WHERE wishlist_id=?',
                                   (wishlist_id,))
                    wishlist_items = cursor.fetchall()
                    if wishlist_items:
                        items_list = '\n'.join(
                            [f'{item[0]} - Estimated: {item[1]} UAH' for item in wishlist_items])
                        client_socket.send(f'Items in wishlist {wishlist_id}:\n{items_list}'.encode('utf-8'))
                    else:
                        client_socket.send(f'No items in wishlist {wishlist_id}.'.encode('utf-8'))
                else:
                    client_socket.send(f'You do not have permission to view this wishlist.'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid wishlist_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error viewing wishlist: {e}')
            client_socket.send('Error viewing wishlist. Please try again.'.encode('utf-8'))


    def user_info(self, client_socket, user, args):
        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                cursor.execute('SELECT username FROM users WHERE user_id=?', (user[0],))
                user_info = cursor.fetchone()
                if user_info:
                    username = user_info[0]
                    cursor.execute(
                        'SELECT u.username FROM friends f JOIN users u ON f.friend_id=u.user_id WHERE f.user_id=?',
                        (user[0],))
                    friends = cursor.fetchall()
                    friends_list = ', '.join([friend[0] for friend in friends])
                    cursor.execute(
                        'SELECT w.wishlist_id, w.wishlist_name, wv.friend_id FROM wishlists w LEFT JOIN wishlist_visibility wv ON w.wishlist_id=wv.wishlist_id WHERE w.user_id=?',
                        (user[0],))
                    wishlists = cursor.fetchall()
                    wishlists_info = ', '.join(
                        [f'Wishlist: {wishlist[1]}, Visible to: {wishlist[2]}' for wishlist in wishlists])
                    response = f'Username: {username}\nFriends: {friends_list}\n{wishlists_info}' if friends_list else f'Username: {username}\nNo friends yet.'
                    client_socket.send(response.encode('utf-8'))
                else:
                    client_socket.send('User not found.'.encode('utf-8'))
        except Exception as e:
            print(f'Error retrieving user information: {e}')
            client_socket.send('Error retrieving user information. Please try again.'.encode('utf-8'))


    def create_wishlist(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: CREATE_WISHLIST wishlist_name'.encode('utf-8'))
            return
        wishlist_name = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                cursor.execute('INSERT INTO wishlists (wishlist_name, user_id) VALUES (?, ?)', (wishlist_name, user[0]))
                wishlist_id = cursor.lastrowid
                cursor.execute('INSERT INTO wishlist_visibility (wishlist_id, friend_id) VALUES (?, ?)',
                               (wishlist_id, user[0]))
                client_socket.send(f'Wishlist "{wishlist_name}" created successfully!'.encode('utf-8'))
        except Exception as e:
            print(f'Error creating wishlist: {e}')
            client_socket.send('Error creating wishlist. Please try again.'.encode('utf-8'))


    def manage_wishlist_visibility(self, client_socket, user, args):
        if len(args) != 3:
            client_socket.send(
                'Invalid command format. Usage: MANAGE_WISHLIST_VISIBILITY wishlist_id friend_username visibility'.encode(
                    'utf-8'))
            return
        wishlist_id, friend_username, visibility = args[0], args[1], args[2]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                wishlist_id = int(wishlist_id)
                cursor.execute('SELECT user_id FROM users WHERE username=?', (friend_username,))
                friend_user = cursor.fetchone()
                if friend_user:
                    friend_user_id = friend_user[0]
                    cursor.execute('SELECT * FROM wishlist_visibility WHERE wishlist_id=? AND friend_id=?',
                                   (wishlist_id, friend_user_id))
                    existing_visibility = cursor.fetchone()
                    if visibility.lower() == 'add' and not existing_visibility:
                        cursor.execute('INSERT INTO wishlist_visibility (wishlist_id, friend_id) VALUES (?, ?)',
                                       (wishlist_id, friend_user_id))
                        client_socket.send(
                            f'User "{friend_username}" added to wishlist visibility successfully!'.encode('utf-8'))
                    elif visibility.lower() == 'remove' and existing_visibility:
                        cursor.execute('DELETE FROM wishlist_visibility WHERE wishlist_id=? AND friend_id=?',
                                       (wishlist_id, friend_user_id))
                        client_socket.send(
                            f'User "{friend_username}" removed from wishlist visibility successfully!'.encode(
                                'utf-8'))
                    else:
                        client_socket.send(
                            f'Invalid visibility or user "{friend_username}" already has visibility.'.encode(
                                'utf-8'))
                else:
                    client_socket.send(f'User "{friend_username}" not found.'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid wishlist_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error managing wishlist visibility: {e}')
            client_socket.send('Error managing wishlist visibility. Please try again.'.encode('utf-8'))

    def assign_item(self, client_socket, user, args):
        if len(args) < 3:
            client_socket.send(
                'Invalid command format. Usage: ASSIGN_ITEM group_id item_name assigned_username'.encode('utf-8'))
            return

        group_id, item_name, assigned_username = args[0], args[1], args[2]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT * FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                if not cursor.fetchone():
                    client_socket.send(
                        f'You are not a member of group {group_id}. Please join the group first.'.encode('utf-8'))
                    return
                cursor.execute('SELECT * FROM items WHERE group_id=? AND item_name=?', (group_id, item_name))
                item = cursor.fetchone()
                if not item:
                    client_socket.send(f'Item "{item_name}" does not exist in group {group_id}.'.encode('utf-8'))
                    return
                cursor.execute('UPDATE items SET assigned_username=? WHERE group_id=? AND item_name=?',
                               (assigned_username, group_id, item_name))
                client_socket.send(
                    f'Item "{item_name}" assigned to user {assigned_username} in group {group_id} successfully!'.encode(
                        'utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error assigning item: {e}')
            client_socket.send('Error assigning item. Please try again.'.encode('utf-8'))


    def list_items_in_group(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: LIST_ITEMS_IN_GROUP group_id'.encode('utf-8'))
            return

        group_id = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT * FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                if not cursor.fetchone():
                    client_socket.send(
                        f'You are not a member of group {group_id}. Please join the group first.'.encode('utf-8'))
                    return
                cursor.execute(
                    'SELECT item_name, estimated_price, purchased_price, receipt_path, assigned_username FROM items WHERE group_id=?',
                    (group_id,))
                items = cursor.fetchall()
                total_estimated_price = sum(item[1] for item in items)
                total_purchased_price = sum(item[2] for item in items if item[2] is not None)

                if items:
                    items_list = '\n'.join([
                        f'{item[0]} - Estimated: {item[1]} UAH, Purchased: {item[2]} UAH (Assigned to user {item[4]}), Receipt: {item[3]}'
                        for item in items])
                    response = f'Items in group {group_id}:\n{items_list}\nTotal Estimated Price: {total_estimated_price} UAH, Total Purchased Price: {total_purchased_price} UAH'
                    client_socket.send(response.encode('utf-8'))
                else:
                    client_socket.send(f'No items in group {group_id}.'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error listing items in group: {e}')
            client_socket.send('Error listing items in group. Please try again.'.encode('utf-8'))


    def add_friend(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: ADD_FRIEND friend_username'.encode('utf-8'))
            return
        friend_username = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                cursor.execute('SELECT user_id FROM users WHERE username=?', (friend_username,))
                friend_user = cursor.fetchone()
                if friend_user:
                    friend_user_id = friend_user[0]
                    cursor.execute('SELECT * FROM friends WHERE user_id=? AND friend_id=?', (user[0], friend_user_id))
                    if cursor.fetchone():
                        client_socket.send(f'User "{friend_username}" is already your friend.'.encode('utf-8'))
                    else:
                        cursor.execute('INSERT INTO friends (user_id, friend_id) VALUES (?, ?)', (user[0], friend_user_id))
                        client_socket.send(
                            f'User "{friend_username}" added to your friends list successfully!'.encode('utf-8'))
                else:
                    client_socket.send(f'User "{friend_username}" not found.'.encode('utf-8'))
        except Exception as e:
            print(f'Error adding friend: {e}')
            client_socket.send('Error adding friend. Please try again.'.encode('utf-8'))


    def add_item(self, client_socket, user, args):
        if len(args) < 3:
            client_socket.send(
                'Invalid command format. Usage: ADD_ITEM group_id item_name estimated_price'.encode('utf-8'))
            return

        group_id, item_name, estimated_price = args[0], args[1], args[2]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT * FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                if not cursor.fetchone():
                    client_socket.send(
                        f'You are not a member of group {group_id}. Please join the group first.'.encode('utf-8'))
                    return
                cursor.execute('INSERT INTO items (group_id, item_name, estimated_price) VALUES (?, ?, ?)',
                               (group_id, item_name, estimated_price))
                client_socket.send(f'Item "{item_name}" added to group {group_id} successfully!'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error adding item: {e}')
            client_socket.send('Error adding item. Please try again.'.encode('utf-8'))


    def mark_purchase(self, client_socket, user, args):
        if len(args) < 4:
            client_socket.send(
                'Invalid command format. Usage: MARK_PURCHASE group_id item_name purchased_price receipt_path'.encode(
                    'utf-8'))
            return

        group_id, item_name, purchased_price, receipt_path = args[0], args[1], args[2], args[3]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT * FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                if not cursor.fetchone():
                    client_socket.send(
                        f'You are not a member of group {group_id}. Please join the group first.'.encode('utf-8'))
                    return
                cursor.execute('UPDATE items SET purchased_price=?, receipt_path=? WHERE group_id=? AND item_name=?',
                               (purchased_price, receipt_path, group_id, item_name))
                client_socket.send(
                    f'Purchase marked for item "{item_name}" in group {group_id} successfully!'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error marking purchase: {e}')
            client_socket.send('Error marking purchase. Please try again.'.encode('utf-8'))


    def create_group(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: CREATE_GROUP group_name'.encode('utf-8'))
            return

        group_name = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                cursor.execute('INSERT INTO groups (group_name, creator_id) VALUES (?, ?)', (group_name, user[0]))
                group_id = cursor.lastrowid
                cursor.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', (group_id, user[0]))
                client_socket.send(f'Group "{group_name}" created successfully!'.encode('utf-8'))
        except Exception as e:
            print(f'Error creating group: {e}')
            client_socket.send('Error creating group. Please try again.'.encode('utf-8'))


    def join_group(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: JOIN_GROUP group_id'.encode('utf-8'))
            return

        group_id = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT * FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                if cursor.fetchone():
                    client_socket.send(f'You are already a member of group {group_id}.'.encode('utf-8'))
                else:
                    cursor.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', (group_id, user[0]))
                    client_socket.send(f'Joined group {group_id} successfully!'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error joining group: {e}')
            client_socket.send('Error joining group. Please try again.'.encode('utf-8'))

    def list_groups(self, client_socket):
        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                cursor.execute('SELECT * FROM groups')
                groups = cursor.fetchall()
                if groups:
                    group_list = '\n'.join([f'{group[0]}. {group[1]}' for group in groups])
                    client_socket.send(f'Available groups:\n{group_list}'.encode('utf-8'))
                else:
                    client_socket.send('No groups available.'.encode('utf-8'))
        except Exception as e:
            print(f'Error listing groups: {e}')
            client_socket.send('Error listing groups. Please try again.'.encode('utf-8'))

    def leave_group(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: LEAVE_GROUP group_id'.encode('utf-8'))
            return

        group_id = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT * FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                if cursor.fetchone():
                    cursor.execute('DELETE FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                    client_socket.send(f'Left group {group_id} successfully!'.encode('utf-8'))
                else:
                    client_socket.send(f'You are not a member of group {group_id}.'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error leaving group: {e}')
            client_socket.send('Error leaving group. Please try again.'.encode('utf-8'))

    def remove_item(self, client_socket, user, args):
        if len(args) != 2:
            client_socket.send('Invalid command format. Usage: REMOVE_ITEM group_id item_name'.encode('utf-8'))
            return

        group_id, item_name = args[0], args[1]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT * FROM group_members WHERE group_id=? AND user_id=?', (group_id, user[0]))
                if not cursor.fetchone():
                    client_socket.send(
                        f'You are not a member of group {group_id}. Please join the group first.'.encode('utf-8'))
                    return
                cursor.execute('DELETE FROM items WHERE group_id=? AND item_name=?', (group_id, item_name))
                client_socket.send(f'Item "{item_name}" removed from group {group_id} successfully!'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error removing item: {e}')
            client_socket.send('Error removing item. Please try again.'.encode('utf-8'))

    def group_members(self, client_socket, user, args):
        if len(args) != 1:
            client_socket.send('Invalid command format. Usage: GROUP_MEMBERS group_id'.encode('utf-8'))
            return

        group_id = args[0]

        try:
            with DatabaseManager(SQLiteDatabaseFactory()) as cursor:
                group_id = int(group_id)
                cursor.execute('SELECT u.user_id, u.username FROM group_members gm JOIN users u ON gm.user_id = u.user_id WHERE gm.group_id=?', (group_id,))
                members = cursor.fetchall()

                if members:
                    members_list = '\n'.join([f'User ID: {member[0]}, Username: {member[1]}' for member in members])
                    client_socket.send(f'Members of group {group_id}:\n{members_list}'.encode('utf-8'))
                else:
                    client_socket.send(f'No members in group {group_id}.'.encode('utf-8'))
        except ValueError:
            client_socket.send('Invalid group_id. Please provide a valid integer.'.encode('utf-8'))
        except Exception as e:
            print(f'Error retrieving group members: {e}')
            client_socket.send('Error retrieving group members. Please try again.'.encode('utf-8'))


if __name__ == "__main__":
    from db import main, DatabaseManager
    main()
    server_instance = Server()
    server_instance.start_server()
