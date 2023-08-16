# BoardWare cloud api

## Configuration

Example

## Generate model from openapi

## Generate Go SDK

```bash
openapi-generator generate -i openapi.yaml -g go \
  -o ./go-sdk
```

## Generate typescript SDK

```bash
openapi-generator generate -i openapi.yaml -g typescript-fetch -o ./ts-sdk \
   --additional-properties=npmName=core-ts-sdk
```

```sql
INSERT INTO accounts (id, created_at, updated_at, email, password,salt, role)
VALUES ("1681137588590612481", "2023-07-18 11:03:29.804", "2023-07-18 11:03:29.804", "dan.chen@boardware.com", "d71416b14e0d3e050639e254466fe1fe7537c50e75fad21da12b8b5e1462d80488847e1a3d57d737cbf9f1046c27c09ff7ac0955c88b6ca40e5853f4c2ad0758", 0x9905071F173336CA28E579600E48B30D, "ROOT");
INSERT INTO services (id, created_at, updated_at, key)
VALUES ("1681137588590612481",  "2023-07-18 11:03:29.804", "2023-07-18 11:03:29.804",
"HelloWorld");
```

```
GOPRIVATE=gitea.svc.boardware.com/bwc/core-api go get -u -f gitea.svc.boardware.com/bwc/core-api
```

```
openapi-go-generator -o . -p coreapi
```
