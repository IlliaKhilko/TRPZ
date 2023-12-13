import abc
import sqlite3
class AbstractDatabaseFactory(abc.ABC):
    @abc.abstractmethod
    def create_connection(self):
        pass
    @abc.abstractmethod
    def create_cursor(self, connection):
        pass

class SQLiteDatabaseFactory(AbstractDatabaseFactory):
    def create_connection(self, database_name='database.db'):
        return sqlite3.connect(database_name)
    def create_cursor(self, connection):
        return connection.cursor()

class PostgreSQLDatabaseFactory(AbstractDatabaseFactory):
    def create_connection(self, database_name='database', user='user', password='password', host='localhost', port=5432,
                          psycopg2=None):
        return psycopg2.connect(database=database_name, user=user, password=password, host=host, port=port)
    def create_cursor(self, connection):
        return connection.cursor()

class CompositeDatabaseFactory(AbstractDatabaseFactory):
    def __init__(self):
        self.factories = []
    def add_factory(self, factory):
        self.factories.append(factory)
    def create_connection(self, *args, **kwargs):
        connections = [factory.create_connection(*args, **kwargs) for factory in self.factories]
        return connections
    def create_cursor(self, connections):
        cursors = [factory.create_cursor(connection) for factory, connection in zip(self.factories, connections)]
        return cursors