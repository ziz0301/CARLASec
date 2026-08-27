import pickle

data_store = {
    b'\xF1\x90': "CARLAREV7DW108177",
    b'\xF1\x91': "CARLAHARDWAREN012",
    b'\xF1\x87': "PARTNUM12345",
    b'\xF1\x89': "SUPPLIER_ID12345",
    b'\xF1\x92': "SYSTEM_NAME"
}

with open('data_store.pkl', 'wb') as file:
    pickle.dump(data_store, file)
