import pandas as pd
import ipaddress
from sklearn.base import BaseEstimator, TransformerMixin

class IPAddressTransformer(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.ip_cols = ['remote_address', 'local_address', 'host_header']

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        X = X.copy()
        for col in self.ip_cols:
            if col in X.columns:
                X[col] = X[col].apply(lambda x: int(ipaddress.IPv4Address(x)) if pd.notnull(x) else 0)
        return X

class RequestUserAgentEncoder(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        X = X.copy()
        if 'request_line' in X.columns:
            X['request_line'] = (X['request_line'] != 'GET / HTTP/1.1').astype(int)
        if 'user_agent' in X.columns:
            X['user_agent'] = (X['user_agent'] != 'curl/8.13.0').astype(int)
        return X
