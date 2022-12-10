import pandas as pd
import matplotlib.pyplot as plt

var = pd.read_excel("ABE_Setup_Runtime.xlsx")

attributes = list(var['Attributes'])
timeMs = list(var['Time(ms)'])

plt.figure(figsize=(10,10))
plt.scatter(timeMs,attributes,marker=".",s=100,c="blue")
plt.title("ABE Setup runtime")
plt.xscale('log', basex=2)
plt.yscale('log')
plt.ylabel("Attributes (universe size)")

plt.xlabel("Milliseconds")
plt.show()

var = pd.read_excel("ABE_Keygen_Runtime.xlsx")

NodesReq = list(var['NodesRequired'])
timeMs = list(var['Time(ms)'])

plt.figure(figsize=(10,10))
plt.scatter(timeMs,NodesReq,marker=".",s=100,c="blue")
plt.title("ABE Keygen runtime")
plt.ylabel("Total # nodes")
plt.xlabel("Milliseconds")
plt.show()

var = pd.read_excel("ABE_Encryption_Runtime.xlsx")

attributes = list(var['Attributes'])
timeMs = list(var['Time(ms)'])

plt.figure(figsize=(10,10))
plt.scatter(timeMs,attributes,marker=".",s=100,c="blue")
plt.title("ABE Encrypt runtime")
plt.ylabel("Attributes")
plt.xlabel("Milliseconds")
plt.show()

var = pd.read_excel("ABE_Decryption_Runtime.xlsx")

attributes = list(var['NodesRequired'])
timeMs = list(var['Time(ms)'])

plt.figure(figsize=(10,10))
plt.scatter(timeMs,attributes,marker=".",s=100,c="blue")
plt.title("ABE Decrypt runtime")
plt.ylabel("Total # nodes that have to be satisfied")
plt.xlabel("Milliseconds")
plt.show()