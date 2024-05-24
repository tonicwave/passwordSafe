import redis
import json
from time import sleep
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class RedApi:
    def __init__(self):
        """simple class to interact with queues. Have fun with the methods"""
        self.host = '127.0.0.1'
        self.db = 0
        self.port = 6379
        self.r = redis.Redis(host=self.host, port=self.port, db=self.db)

    def enqueue(self, key: str, message: dict):
        """Send message to the Redis queue, using the queue name as the key

        message should be in the form:
        {"username": "some-username",
         "password": "s0m3P@ssw0rD",
        }
        """
        try:
            json_message = json.dumps(message)
            logger.debug(f"json_message {json_message}")

            self.r.lpush(key, json_message)
            logger.debug(f"JSON message stored under the queue '{key}'")
            return True
        except Exception as e:
            logger.error("Error sending message to queue %s", e)
            return False

    def dequeue(self, key: str):
        """watch the Redis queue, using the queue key"""
        item = self.r.lpop(key)
        if item:
            item_str = item.decode('utf-8')
            logger.debug(f"I found the item: {item_str}")
            sleep(1)
            return item_str
        else:
            sleep(1)
            logger.debug(f"Looking for items in {key}...")
            return
