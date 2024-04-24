package algosdkwrapper

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand-sdk/v2/abi"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// DeployArc4AppIfNeeded lookups the appName among the apps deployed in the local
// network by the main account. If the app is not found, it deploys it.
// If found, it checks that the app is up to date with the latest compiled version
// and if not it deletes it and deploys the new version.
//
// The function expects to find the files:
// - dir + appName + ".approval.teal"
// - dir + appName + ".clear.teal"
// - dir + appName + ".arc32.json"
//
// A local network must be running
func DeployArc4AppIfNeeded(appName string, dir string) (
	appId uint64, err error) {

	algodClient := GetAlgodClient()

	approvalBin, err := CompileTealFromFile(filepath.Join(dir,
		appName+".approval.teal"))
	if err != nil {
		return 0, fmt.Errorf("failed to read approval program: %v", err)
	}
	clearBin, err := CompileTealFromFile(filepath.Join(dir,
		appName+".clear.teal"))
	if err != nil {
		return 0, fmt.Errorf("failed to read clear program: %v", err)
	}
	schema, err := ReadArc32Schema(filepath.Join(dir, appName+".arc32.json"))
	if err != nil {
		return 0, fmt.Errorf("failed to read arc32 schema: %v", err)
	}

	creator, err := GetDefaultAccount()
	if err != nil {
		return 0, fmt.Errorf("failed to get localnet default account: %v", err)
	}

	app, err := GetAppByName(appName, creator.Address.String())
	if err != nil {
		return 0, fmt.Errorf("failed to read the blockchain: %v", err)
	}
	// if app exists and is up to date, return its id, otherwise delete it
	if app != nil {
		onchainApproval := app.Params.ApprovalProgram
		onchainClear := app.Params.ClearStateProgram
		if bytes.Equal(onchainApproval, approvalBin) &&
			bytes.Equal(onchainClear, clearBin) {
			fmt.Printf("App %s already exists with id %d and is up to date\n",
				appName, app.Id)
			return app.Id, nil
		} else {
			fmt.Printf("App %s exists but has been modified, deleting it...\n",
				appName)
			sp, err := algodClient.SuggestedParams().Do(context.Background())
			if err != nil {
				return 0, fmt.Errorf("failed to make delete txn: %v", err)
			}
			deleteMethod, err := schema.Contract.GetMethodByName("update")
			if err != nil {
				return 0, fmt.Errorf("failed to get update method: %v", err)
			}
			txn, err := transaction.MakeApplicationDeleteTx(
				app.Id, [][]byte{deleteMethod.GetSelector()}, nil, nil, nil, sp,
				creator.Address, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
			)
			if err != nil {
				return 0, fmt.Errorf("failed to make delete txn: %v", err)
			}
			_, err = SendTxn(txn, creator)
			if err != nil {
				return 0, fmt.Errorf("error sending delete transaction:  %v", err)
			}
		}
	}

	// create app
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return 0, fmt.Errorf("error getting suggested txn params: %v", err)
	}
	createMethod, err := schema.Contract.GetMethodByName("create")
	if err != nil {
		return 0, fmt.Errorf("failed to get create method: %v", err)
	}
	extraPages := uint32(len(approvalBin)) / 2048
	if extraPages > 3 {
		return 0, fmt.Errorf("approval program too large even for extra pages: "+
			"%d bytes", len(approvalBin))
	}
	txn, err := transaction.MakeApplicationCreateTxWithExtraPages(
		false, approvalBin, clearBin,
		types.StateSchema{NumUint: schema.State.Global.NumUints,
			NumByteSlice: schema.State.Global.NumByteSlices},
		types.StateSchema{NumUint: schema.State.Local.NumUints,
			NumByteSlice: schema.State.Local.NumByteSlices},
		[][]byte{createMethod.GetSelector(), []byte(appName)},
		nil, nil, nil,
		sp, creator.Address, nil,
		types.Digest{}, [32]byte{}, types.ZeroAddress, extraPages,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to make create txn: %v", err)
	}
	confirmedTxn, err := SendTxn(txn, creator)
	if err != nil {
		return 0, fmt.Errorf("error sending create transaction:  %v", err)
	}
	fmt.Printf("App %s created with id %d\n", appName,
		confirmedTxn.ApplicationIndex)
	return confirmedTxn.ApplicationIndex, nil
}

// Arc32Schema defines a partial ARC32 schema
type Arc32Schema struct {
	Source struct {
		Approval string `json:"approval"`
		Clear    string `json:"clear"`
	} `json:"source"`
	State struct {
		Global struct {
			NumByteSlices uint64 `json:"num_byte_slices"`
			NumUints      uint64 `json:"num_uints"`
		} `json:"global"`
		Local struct {
			NumByteSlices uint64 `json:"num_byte_slices"`
			NumUints      uint64 `json:"num_uints"`
		} `json:"local"`
	} `json:"state"`
	Contract abi.Contract `json:"contract"`
}

// ReadArc32Schema reads an ARC32 schema from a JSON file
func ReadArc32Schema(filepath string) (
	schema *Arc32Schema, err error) {

	file, err := os.Open(filepath)
	if err != nil {
		return schema, fmt.Errorf("error opening schema file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&schema); err != nil {
		return schema, fmt.Errorf("error decoding schema file: %v", err)
	}

	return schema, nil
}

// CompileTealFromFile reads a teal file and returns a compiled b64 binary.
// A local network must be running
func CompileTealFromFile(tealFile string) ([]byte, error) {
	algodClient := GetAlgodClient()

	teal, err := os.ReadFile(tealFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s from file: %v", tealFile, err)
	}

	result, err := algodClient.TealCompile(teal).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to compile %s: %v", tealFile, err)
	}
	binary, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		log.Fatalf("failed to decode approval program: %v", err)
	}

	return binary, nil
}

// SendTxn signs and sends a transaction to the network.
// A local network must be running
func SendTxn(txn types.Transaction, account *crypto.Account) (
	*models.PendingTransactionInfoResponse, error) {
	algodClient := GetAlgodClient()
	var err error
	if account == nil {
		account, err = GetDefaultAccount()
		if err != nil {
			return nil, fmt.Errorf("failed to get localnet default account: %s",
				err)
		}
	}

	txid, stx, err := crypto.SignTransaction(account.PrivateKey, txn)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}
	_, err = algodClient.SendRawTransaction(stx).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v", err)
	}
	confirmedTxn, err := transaction.WaitForConfirmation(algodClient, txid,
		4, context.Background())
	if err != nil {
		return nil, fmt.Errorf("error waiting for confirmation:  %v", err)
	}
	return &confirmedTxn, nil
}

// GetAppByName returns the app created by creatorAddress with the name appName.
// If the app is not found, it returns nil.
// A local network must be running
func GetAppByName(appName string, creatorAddress string) (
	*models.Application, error) {
	algodClient := GetAlgodClient()
	appsByCreator, err := algodClient.AccountInformation(creatorAddress).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get account information: %v", err)
	}
	for _, app := range appsByCreator.CreatedApps {
		for _, global := range app.Params.GlobalState {
			key, _ := base64.StdEncoding.DecodeString(global.Key)
			value, _ := base64.StdEncoding.DecodeString(global.Value.Bytes)
			if bytes.Equal(key, []byte("app_name")) &&
				bytes.Equal(value, []byte(appName)) {
				return &app, nil
			}
		}
	}
	return nil, nil
}

// CallVerifyMethod calls a verifier app with the given proof and public inputs.
// If account is nil, it uses the default localnet account.
// If simulate is true, it simulates the call instead of sending it, adding the
// maximum extra opcode budget.
// A local network must be running
func CallVerifyMethod(appId uint64, account *crypto.Account, proofFilename string,
	publicInputsFilename string, schema *Arc32Schema, simulate bool) (
	*transaction.ABIMethodResult, error) {

	algodClient := GetAlgodClient()
	var err error
	if account == nil {
		account, err = GetDefaultAccount()
		if err != nil {
			return nil,
				fmt.Errorf("failed to get localnet default account: %v", err)
		}
	}
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested txn params: %v", err)
	}
	verifyMethod, err := schema.Contract.GetMethodByName("verify")
	if err != nil {
		return nil, fmt.Errorf("failed to get verify method: %v", err)
	}
	proof, err := os.ReadFile(proofFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %v", err)
	}
	publicInputs, err := os.ReadFile(publicInputsFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public inputs file: %v", err)
	}
	var proofAbi, publicInputsAbi [][]byte
	for i := 0; i < len(proof); i += 32 {
		proofAbi = append(proofAbi, proof[i:i+32])
	}
	for i := 0; i < len(publicInputs); i += 32 {
		publicInputsAbi = append(publicInputsAbi, publicInputs[i:i+32])
	}

	var atc = transaction.AtomicTransactionComposer{}
	signer := transaction.BasicAccountTransactionSigner{Account: *account}
	txnParams := transaction.AddMethodCallParams{
		AppID:           appId,
		Sender:          account.Address,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          signer,
		Method:          verifyMethod,
		MethodArgs:      []interface{}{proofAbi, publicInputsAbi},
	}
	if err := atc.AddMethodCall(txnParams); err != nil {
		return nil, fmt.Errorf("failed to add method call: %v", err)
	}
	if simulate {
		simReq := models.SimulateRequest{ExtraOpcodeBudget: 320000}
		simRes, err_ := atc.Simulate(context.Background(), algodClient, simReq)
		if err_ != nil {
			return nil, fmt.Errorf("failed to simulate verify txn: %v", err)
		}
		budgetConsumed := simRes.SimulateResponse.TxnGroups[0].AppBudgetConsumed
		fmt.Println("Budget consumed: ", budgetConsumed)
		abiResult := simRes.MethodResults[len(simRes.MethodResults)-1]
		return &abiResult, nil
	}
	atcRes, err := atc.Execute(algodClient, context.Background(), 4)
	if err != nil {
		return nil, fmt.Errorf("failed to execute verify txn: %v", err)
	}
	return &atcRes.MethodResults[len(atcRes.MethodResults)-1], nil
}

// ExecuteAbiCall calls an abi method on an app.
// A local network must be running
func ExecuteAbiCall(appId uint64, account *crypto.Account, schema *Arc32Schema,
	methodName string, oc types.OnCompletion, methodArgs []interface{}) (
	*transaction.ExecuteResult, error) {

	algodClient := GetAlgodClient()
	var err error
	if account == nil {
		account, err = GetDefaultAccount()
		if err != nil {
			return nil, fmt.Errorf("failed to get localnet default account: %v",
				err)
		}
	}
	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested txn params: %v", err)
	}
	method, err := schema.Contract.GetMethodByName(methodName)
	if err != nil {
		return nil, fmt.Errorf("failed to get method %s: %v", methodName, err)
	}

	var atc = transaction.AtomicTransactionComposer{}
	signer := transaction.BasicAccountTransactionSigner{Account: *account}
	txnParams := transaction.AddMethodCallParams{
		AppID:           appId,
		Sender:          account.Address,
		SuggestedParams: sp,
		OnComplete:      oc,
		Signer:          signer,
		Method:          method,
		MethodArgs:      methodArgs,
	}
	if err := atc.AddMethodCall(txnParams); err != nil {
		return nil, fmt.Errorf("failed to add method call: %v", err)
	}
	res, err := atc.Execute(algodClient, context.Background(), 4)
	if err != nil {
		return nil, fmt.Errorf("failed to execute make_immutable txn: %v", err)
	}
	return &res, nil
}

// GetDefaultAccount returns the default account for the local network
// A local network must be running
func GetDefaultAccount() (account *crypto.Account, err error) {
	accts, err := GetSandboxAccounts()
	if err != nil {
		return account, fmt.Errorf("failed to get localnet accounts: %s.\n"+
			"Make sure you are running a local Algorand network with default "+
			"parameters:\nalgod_url -> %s\nalgod_token -> %s",
			err, ALGOD_URL, ALGOD_TOKEN)
	}
	return &accts[0], nil
}
