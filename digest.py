# -*- coding: utf-8 -*-

import pandas,pyarrow
import redis
from sqlalchemy import create_engine
import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import threading
import logging

logging.basicConfig(level = logging.WARNING,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# 打印pandas dataframe对象时设置的选项(调试阶段用)
pandas.set_option('display.max_columns', None)
pandas.set_option('max_colwidth',50)
pandas.set_option('display.width',200)

# JOB执行周期(秒)
job_interval = 60
# 排除的schema_name
exclude_schema_name = ['performance_schema','information_schema']
# 周期内执行频率的阈值,超过该值才入库
count_threshold = 3

rs = redis.StrictRedis(host='redis_ip',port=6379)
manager_db = 'mysql+pymysql://username:password@manager_db_ip:3306/digest_stat?charset=utf8&autocommit=true'
manager_engine = create_engine(manager_db,pool_size=5,max_overflow=0,)

# 全局连接池字典
db_pool_dic = {}

def get_instance():
    sql_instance = "select instance_name,ip_addr,port,user_name,password," \
                   "case when update_time > DATE_SUB(now(),INTERVAL " + str(job_interval * 1.5) + " second) then 'changed' else 'unchanged' end ischanged " \
                   "from db_instance "\
                   "where status=0"
    df_instance = pandas.read_sql(sql_instance, con=manager_engine)
    return df_instance

def check_db_pool():
    df_instance = get_instance()
    for instance in list(db_pool_dic.keys()):
        # 数据库中不存在的instance,删除
        if instance not in list(df_instance['instance_name']):
            del db_pool_dic[instance]
            logger.warning("db pool delete: " + instance)
            continue
        # 检查现有连接池的有效性,无效则删除
        try:
            conn = db_pool_dic.get(instance).raw_connection()
            cursor = conn.cursor()
            cursor.execute('select 1')
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
        except:
            del db_pool_dic[instance]
            logger.warning("db pool delete: " + instance)

    # 创建不存在的连接池(新增或失效被踢的)
    # 重置1分钟内有修改的连接池
    for index, row in df_instance.iterrows():
        if (not db_pool_dic.get(row['instance_name']) or row['ischanged'] == 'changed'):
            if db_pool_dic.get(row['instance_name']):
                del db_pool_dic[row['instance_name']]
                logger.warning("db pool delete: " + row['instance_name'])
            conn = 'mysql+pymysql://' + row['user_name'] + ':' + str(row['password']) + '@' + row['ip_addr'] + ':' + str(row['port']) + '/performance_schema?charset=utf8&autocommit=true'
            try:
                db_engine = create_engine(conn,pool_size=1,max_overflow=0,connect_args={'connect_timeout': 1})
                conn = db_engine.raw_connection()
                cursor = conn.cursor()
                cursor.execute('select 1')
                rows = cursor.fetchall()
                cursor.close()
                conn.close()
                db_pool_dic[row['instance_name']] = db_engine
                logger.warning("db pool add: " + row['instance_name'])
            except:
                logger.warning("connect to " + row['instance_name'] + " failed")


def update_digest_stat(checksum, digest_text, event_time):
    sample = digest_text[:30]
    conn = manager_engine.raw_connection()
    cursor = conn.cursor()
    cursor.execute('select count(*) from global_query_review where checksum=%s',(checksum))
    result = cursor.fetchall()
    rescnt = result[0][0]
    if rescnt == 0:
        cursor.execute('insert into global_query_review(checksum,fingerprint,sample,first_seen,last_seen) values(%s,%s,%s,%s,%s)',(checksum,digest_text,sample,event_time,event_time))
    elif rescnt == 1:
        cursor.execute('update global_query_review set last_seen = %s where checksum = %s',(event_time, checksum))
    else:
        pass
    cursor.close()
    conn.close()

# events_statements_summary_by_digest 1分钟内是否truncate
def truncate_judge(db_engine):
    conn = db_engine.raw_connection()
    cursor = conn.cursor()
    cursor.execute('select unix_timestamp(now()) - unix_timestamp(min(first_seen)) from events_statements_summary_by_digest')
    result = cursor.fetchall()
    truncate_seconds = result[0][0]
    cursor.close()
    conn.close()
    if truncate_seconds < job_interval:
        return True
    else:
        return False

# port 支持多实例部署
def handle_db(instance_name):
    # 获取目标库连接
    db_engine = db_pool_dic.get(instance_name)
    if not db_engine:
        return
    # 如果当前周期内被truncate,则当前JOB不处理
    if truncate_judge(db_engine):
        return
    sql_full = "select concat('" + instance_name + "','-'" + ",digest," + "'-'," + "ifnull(schema_name,'unknow')" + ") checksum" + ",sum(count_star) count_star " \
               "from events_statements_summary_by_digest where digest is not NULL " \
               "group by checksum"

    sql_1min = "select concat('" + instance_name + "','-'" + ",digest," + "'-'," + "ifnull(schema_name,'unknow')" + ") checksum" + ",ifnull(schema_name,'unknow') as db_max," \
               "count_star,digest_text,round(avg_timer_wait/1000000000,1) query_time_avg " \
               "from events_statements_summary_by_digest " \
               "where LAST_SEEN > DATE_SUB(now(),INTERVAL 1 minute) " \
               "and digest is not NULL"

    context = pyarrow.default_serialization_context()
    redis_key_name = 'full-digest-' + instance_name

    df_full_last_bytes = rs.get(redis_key_name)
    # 两个SQL写一起,降低数据遗漏的可能性
    df_1min = pandas.read_sql(sql=sql_1min, con=db_engine)
    df_full = pandas.read_sql(sql=sql_full, con=db_engine)

    if df_full_last_bytes:
        df_full_last = context.deserialize(df_full_last_bytes)
        df_merge = pandas.merge(df_full_last,df_1min,how='right',left_on=['checksum'],right_on=['checksum'])
        df_merge.fillna({'count_star_x':0,'db_max':'unknow'},inplace=True)
        df_merge["ts_cnt"] = df_merge.apply(lambda x: x["count_star_y"] - x["count_star_x"], axis=1)
        df_digest_count = pandas.DataFrame(df_merge,columns=['checksum','db_max','ts_cnt','query_time_avg'])[(df_merge.ts_cnt >= count_threshold) & (~df_merge.db_max.isin(exclude_schema_name) 
)]
        event_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        df_digest_count["ts_min"] = event_time
        df_digest_count["ts_max"] = event_time
        df_digest_count["hostname_max"] = instance_name
        df_digest_count.to_sql('global_query_review_history', manager_db, index=False, if_exists='append')

        df_digest_text = pandas.DataFrame(df_merge,columns=['checksum','digest_text'])[(df_merge.ts_cnt >= count_threshold) & (~df_merge.db_max.isin(exclude_schema_name) )]
        for index,row in df_digest_text.iterrows():
            update_digest_stat(row['checksum'],row['digest_text'], event_time)

    df_full_bytes = context.serialize(df_full).to_buffer().to_pybytes()
    rs.set(redis_key_name,df_full_bytes)
    rs.expire(redis_key_name,job_interval + 30)

def handle_db_all():
    df_instance = get_instance()
    for index, row in df_instance.iterrows():
        # threading.Thread(target=handle_db, args=(row['instance_name'], row['ip_addr'], row['port'])).start()
        threading.Thread(target=handle_db, args=(row['instance_name'],)).start()

if __name__ == '__main__':
    scheduler = BlockingScheduler()
    scheduler.add_job(check_db_pool, 'interval', seconds=job_interval, id='check_db_pool', max_instances=10,coalesce=True, misfire_grace_time=30)
    scheduler.add_job(handle_db_all, 'interval', seconds=job_interval, id='handle_db_all', max_instances=10,coalesce=True, misfire_grace_time=30);
    scheduler.start()
