from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import text
from application import db
from flask import current_app as app
from datetime import datetime
import decimal, datetime, json

class ResultHelper:
    @classmethod
    def alchemyencoder(cls, obj):
        """JSON encoder function for SQLAlchemy special classes."""
        if isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, decimal.Decimal):
            return float(obj)
        else:
            return obj

    @classmethod
    def resultproxy_to_dict_list(cls, sql_alchemy_rowset):
        return [{tuple[0]: cls.alchemyencoder(tuple[1]) for tuple in rowproxy.items()}
                for rowproxy in sql_alchemy_rowset]


class BaseHelper:
    @staticmethod
    def my_exception(ex, sql, bind_params):
        type_exception = type(ex).__name__
        message = [str(x) for x in ex.args]
        log_level = app.logger.critical if type_exception == 'OperationalError' else app.logger.error
        log_level(f'[SQL | {sql} | BIND_PARAMS | {bind_params}] [Exception | ' + ''.join(message) + ']')

        return message

    @staticmethod
    def get_all(sql, bind_params={}):
        r = None
        try:
            r = ResultHelper.resultproxy_to_dict_list(db.engine.execute(text(sql), bind_params).fetchall())
        except Exception as e:  # work on python 3.x
            r = BaseHelper.my_exception(e, sql, bind_params)
        return r

    @staticmethod
    def get_one(sql, bind_params={}):
        r = None
        try:
            r = db.engine.execute(text(sql).execution_options(autocommit=True), bind_params).first()
            r = json.loads(json.dumps(dict(r), default=ResultHelper.alchemyencoder)) if r is not None else r            
        except Exception as e:  # work on python 3.x
            r = BaseHelper.my_exception(e, sql, bind_params)
        return r

    @staticmethod
    def query(sql, bind_params={}, commit=True):
        r = None
        try:
            r = db.engine.execute(text(sql).execution_options(autocommit=commit), bind_params)
        except Exception as e:  # work on python 3.x
            r = BaseHelper.my_exception(e, sql, bind_params)
        return r

    @staticmethod
    def generate_insert_query(table, dictionary):
        # Get all "keys" inside "values" key of dictionary (column names)
        columns = ', '.join(dictionary.keys())
        # Get all "values" inside "values" key of dictionary (insert values)
        values = ', '.join('{0}'.format(l) if isinstance(l, bool) else "'{0}'".format(l) for l in dictionary.values())
        # Generate INSERT query
        q = f"INSERT INTO {table} ({columns}) VALUES ({values})"
        return q

    @staticmethod
    def generate_insert_placeholder(table, list_cols):
        columns = ', '.join(list_cols)
        placeholders = ":" + ', :'.join(list_cols)
        q = f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) returning id"
        return q

    @staticmethod
    def generate_update_query(table, dfields, condicio):
        pairs = (', '.join(
            [x + "=" + ("{0}".format(y) if isinstance(y, bool) else "'{0}'".format(y)) for x, y in dfields.items()]))
        q = f"UPDATE {table} SET {pairs} WHERE {condicio}"
        return q

    @staticmethod
    def generate_update_placeholder(table, list_cols, placeholder_condicio):
        pairs = ', '.join([col + "=:" + col for col in list_cols])
        q = f"UPDATE {table} SET {pairs} WHERE {placeholder_condicio}"
        return q

    @staticmethod
    def entity_exists(table, condicio, bind_params={}):
        sql = f"SELECT count(*) as total FROM {table} WHERE {condicio}"
        r = db.engine.execute(text(sql), bind_params).first()
        return True if r is not None and r['total']>0 else False


class BaseModel(db.Model):
    __abstract__ = True

    def to_dict(self):
        return dict([(k, getattr(self, k)) for k in self.__dict__.keys() if not k.startswith("_")])

    def save(self, commited=True):
        if not self.id:
            db.session.add(self)
        if commited:
            db.session.commit()
        return self
