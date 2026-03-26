# Architectural Flow
BlockStart

  [BLOCK_PROLOGUE serial]
  TxnCallFrame (beacon root)
  AccountAccessListHeader (BLOCK_PROLOGUE)
  AccountAccess*
  StorageAccess*

  [HEADERS parallel]
  TxnHeaderStart(0)
  TxnAccessListEntry*(0)
  TxnAuthListEntry*(0)
  TxnHeaderEnd(0)
  TxnHeaderStart(2)
  TxnHeaderEnd(2)
  TxnHeaderStart(1)
  TxnHeaderEnd(1)
  ...

  [OUTPUT EVENTS parellel fiber]
  TxnEvmOutput(0)
  TxnLog*(0)
  TxnCallFrame*(0)
  AccountAccessListHeader (TRANSACTION, txn=0)
  AccountAccess*(0)
  StorageAccess*(0)
  TxnEnd(0)

  TxnEvmOutput(1)
  ...
  TxnEnd(1)

  TxnEvmOutput(2)
  ...
  TxnEnd(2)

  [BLOCK_EPILOGUE serial]
  AccountAccessListHeader (BLOCK_EPILOGUE)
  AccountAccess*
  StorageAccess*

BlockEnd
