# TA静的解析システム - 処理フロー

## 全体処理フロー

```mermaid
graph TB
    Start([開始]) --> Clean[依存関係クリーンアップ]
    Clean --> P1[Phase 1-2: データベース構築と関数分類]
    P1 --> P3[Phase 3: シンク特定]
    P3 --> P4[Phase 4: 候補フロー生成]
    P4 --> P5[Phase 5: テイント解析]
    P5 --> P6[Phase 6: レポート生成]
    P6 --> End([終了])
    
    style P1 fill:#e1f5fe
    style P3 fill:#fff3e0
    style P4 fill:#f3e5f5
    style P5 fill:#fce4ec
    style P6 fill:#e8f5e9
```

## Phase 0: 依存関係クリーンアップ & ビルド

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> CheckStale{古い依存関係ファイル<br/>存在?}
    
    CheckStale -->|Yes| ScanDeps[「*.d」ファイルをスキャン]
    CheckStale -->|No| TryBuild
    
    ScanDeps --> CheckPath{「/mnt/disk/toolschain」<br/>を含む?}
    CheckPath -->|Yes| DeleteFile[ファイル削除]
    CheckPath -->|No| NextFile[次のファイル]
    
    DeleteFile --> NextFile
    NextFile --> MoreFiles{他の.dファイル<br/>存在?}
    MoreFiles -->|Yes| CheckPath
    MoreFiles -->|No| TryBuild[ビルド試行開始]
    
    TryBuild --> CheckBuildSh{build.sh<br/>存在?}
    CheckBuildSh -->|Yes| RunBear1[bear -- ./build.sh]
    CheckBuildSh -->|No| CheckNdkBuild
    
    RunBear1 --> CheckDB1{compile_commands.json<br/>生成成功?}
    CheckDB1 -->|Yes| ExtractTA
    CheckDB1 -->|No| CheckNdkBuild
    
    CheckNdkBuild{ndk_build.sh<br/>存在?}
    CheckNdkBuild -->|Yes| RunBear2[bear -- ./ndk_build.sh]
    CheckNdkBuild -->|No| CheckMakefile
    
    RunBear2 --> CheckDB2{compile_commands.json<br/>生成成功?}
    CheckDB2 -->|Yes| ExtractTA
    CheckDB2 -->|No| CheckMakefile
    
    CheckMakefile{Makefile<br/>存在?}
    CheckMakefile -->|Yes| RunBear3[bear -- make]
    CheckMakefile -->|No| CheckTaMakefile
    
    RunBear3 --> CheckDB3{compile_commands.json<br/>生成成功?}
    CheckDB3 -->|Yes| ExtractTA
    CheckDB3 -->|No| CheckTaMakefile
    
    CheckTaMakefile{ta/Makefile<br/>存在?}
    CheckTaMakefile -->|Yes| RunBear4[bear -- make -C ta V=1]
    CheckTaMakefile -->|No| CheckCMake
    
    RunBear4 --> CheckDB4{compile_commands.json<br/>生成成功?}
    CheckDB4 -->|Yes| ExtractTA
    CheckDB4 -->|No| CheckCMake
    
    CheckCMake{CMakeLists.txt<br/>存在?}
    CheckCMake -->|Yes| RunCMake[cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON]
    CheckCMake -->|No| GenerateDummy
    
    RunCMake --> CheckDB5{compile_commands.json<br/>生成成功?}
    CheckDB5 -->|Yes| ExtractTA
    CheckDB5 -->|No| GenerateDummy
    
    ExtractTA[TAディレクトリの<br/>エントリを抽出]
    ExtractTA --> ValidateEntries{全ての*.cファイル<br/>が含まれている?}
    
    ValidateEntries -->|Yes| SaveDB[compile_commands.json<br/>として保存]
    ValidateEntries -->|No| GenerateDummy
    
    GenerateDummy[ダミーDB生成]
    GenerateDummy --> CollectCFiles[*.c ファイル収集]
    CollectCFiles --> CreateEntries[コンパイルエントリ作成<br/>-I&#123;ta_dir&#125;<br/>-I&#123;ta_dir&#125;/include<br/>-I&#123;devkit&#125;/include]
    CreateEntries --> SaveDB
    
    SaveDB --> End([終了])
    
    style ScanDeps fill:#ffe0b2
    style TryBuild fill:#e1f5fe
    style GenerateDummy fill:#ffccbc
    style SaveDB fill:#c8e6c9
```

## Phase 1-2: データベース構築と関数分類

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadDB[compile_commands.json<br/>読み込み]
    
    LoadDB --> ParseLoop[各ソースファイルを<br/>パース]
    
    ParseLoop --> NormalizeArgs[コンパイル引数を正規化<br/>-I, -D, -include等を抽出]
    
    NormalizeArgs --> AddIncludes[インクルードパス追加<br/>1. ta/include<br/>2. ta/<br/>3. devkit/include]
    
    AddIncludes --> ParseAST[libclangで<br/>AST構築]
    
    ParseAST --> CheckErrors{パースエラー?}
    CheckErrors -->|Yes| RecordError[エラー記録<br/>続行]
    CheckErrors -->|No| ExtractDecls
    
    RecordError --> NextFile{他のファイル<br/>ある?}
    
    ExtractDecls[関数・マクロ抽出]
    ExtractDecls --> WalkAST[AST走査]
    
    WalkAST --> CheckNode{ノードタイプ?}
    
    CheckNode -->|FUNCTION_DECL| ExtractFunc[関数情報抽出<br/>・name<br/>・file/line<br/>・is_definition<br/>・is_static]
    
    CheckNode -->|MACRO_DEFINITION| ExtractMacro[マクロ情報抽出<br/>・name<br/>・params<br/>・file/line]
    
    CheckNode -->|その他| NextNode[次のノード]
    
    ExtractFunc --> StoreDecl[宣言情報保存]
    ExtractMacro --> StoreDecl
    StoreDecl --> NextNode
    
    NextNode --> MoreNodes{他のノード<br/>ある?}
    MoreNodes -->|Yes| CheckNode
    MoreNodes -->|No| NextFile
    
    NextFile -->|Yes| ParseLoop
    NextFile -->|No| ClassifyPhase[分類フェーズ開始]
    
    ClassifyPhase --> CollectDefined[定義済み関数の収集]
    
    CollectDefined --> IsDefinition{is_definition<br/>== true?}
    IsDefinition -->|Yes| CheckProjectPath{プロジェクト内<br/>のファイル?}
    IsDefinition -->|No| NextDecl1
    
    CheckProjectPath -->|Yes| AddToUserDefined[ユーザ定義として記録<br/>static関数は<br/>ファイル名付きで管理]
    CheckProjectPath -->|No| NextDecl1
    
    AddToUserDefined --> NextDecl1[次の宣言]
    NextDecl1 --> MoreDecls1{他の宣言<br/>ある?}
    MoreDecls1 -->|Yes| IsDefinition
    MoreDecls1 -->|No| ClassifyDecls
    
    ClassifyDecls[宣言の分類]
    ClassifyDecls --> ProcessDecl[各宣言を処理]
    
    ProcessDecl --> CheckKind{宣言の種類?}
    
    CheckKind -->|関数| CheckFuncDef{定義済み?}
    CheckFuncDef -->|Yes in Project| SkipForward[前方宣言として<br/>スキップ]
    CheckFuncDef -->|No| AddExternal1[外部関数として<br/>追加]
    
    CheckKind -->|マクロ| CheckMacroLoc{マクロの場所?}
    CheckMacroLoc -->|Project内| CheckIncludeDir{include/配下?}
    CheckMacroLoc -->|Project外| AddExternal2[外部マクロとして<br/>追加]
    
    CheckIncludeDir -->|Yes| AddExternal3[外部APIとして<br/>追加]
    CheckIncludeDir -->|No| CheckMacroType{関数マクロ?}
    
    CheckMacroType -->|Yes| AddExternal4[外部として追加]
    CheckMacroType -->|No| SkipConstMacro[定数マクロ<br/>スキップ]
    
    SkipForward --> NextDecl2
    AddExternal1 --> NextDecl2
    AddExternal2 --> NextDecl2
    AddExternal3 --> NextDecl2
    AddExternal4 --> NextDecl2
    SkipConstMacro --> NextDecl2
    
    NextDecl2[次の宣言] --> MoreDecls2{他の宣言<br/>ある?}
    MoreDecls2 -->|Yes| ProcessDecl
    MoreDecls2 -->|No| Deduplicate
    
    Deduplicate[重複排除]
    Deduplicate --> SaveResults[結果保存<br/>phase12.json]
    
    SaveResults --> End([終了])
    
    style LoadDB fill:#e1f5fe
    style ParseAST fill:#fff9c4
    style ClassifyPhase fill:#f3e5f5
    style SaveResults fill:#c8e6c9
```

## Phase 3: シンク特定

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadPhase12[phase12.json<br/>読み込み]
    
    LoadPhase12 --> ExtractExternal[外部宣言リスト<br/>抽出]
    
    ExtractExternal --> ScanUserFuncs[ユーザ定義関数を<br/>スキャン]
    
    ScanUserFuncs --> SkipEntry{エントリポイント<br/>関数?}
    SkipEntry -->|Yes| NextUserFunc
    SkipEntry -->|No| ExtractCode[関数コード抽出]
    
    ExtractCode --> ParseCalls[関数呼び出しを<br/>正規表現で抽出]
    
    ParseCalls --> CheckExternal{外部関数<br/>呼び出し?}
    CheckExternal -->|Yes| AddToCallList[呼び出しリストに<br/>追加]
    CheckExternal -->|No| NextCall
    
    AddToCallList --> NextCall[次の呼び出し]
    NextCall --> MoreCalls{他の呼び出し<br/>ある?}
    MoreCalls -->|Yes| CheckExternal
    MoreCalls -->|No| NextUserFunc
    
    NextUserFunc[次のユーザ関数] --> MoreUserFuncs{他のユーザ<br/>関数ある?}
    MoreUserFuncs -->|Yes| SkipEntry
    MoreUserFuncs -->|No| InitAnalysis
    
    InitAnalysis[シンク解析開始]
    InitAnalysis --> CheckRAG{RAG有効?}
    
    CheckRAG -->|Yes| InitRAGClient[RAGクライアント<br/>初期化]
    CheckRAG -->|No| InitLLM
    
    InitRAGClient --> BuildIndex{インデックス<br/>構築済み?}
    BuildIndex -->|No| BuildVectorStore[ベクトルストア<br/>構築]
    BuildIndex -->|Yes| InitLLM
    
    BuildVectorStore --> InitLLM[LLMクライアント<br/>初期化]
    
    InitLLM --> ConfigureRetry[リトライハンドラー<br/>設定]
    
    ConfigureRetry --> AnalyzeLoop[各外部関数を<br/>解析]
    
    AnalyzeLoop --> UseRAG{RAG使用?}
    
    UseRAG -->|Yes| SearchRAG[RAGで関連情報<br/>検索]
    UseRAG -->|No| PreparePrompt
    
    SearchRAG --> SelectPrompt{RAG結果<br/>あり?}
    SelectPrompt -->|Yes| LoadRAGPrompt[RAG用プロンプト<br/>読み込み]
    SelectPrompt -->|No| LoadBasicPrompt[基本プロンプト<br/>読み込み]
    
    LoadRAGPrompt --> FormatPrompt[プロンプト<br/>フォーマット]
    LoadBasicPrompt --> FormatPrompt
    PreparePrompt[プロンプト準備] --> FormatPrompt
    
    FormatPrompt --> CallLLM[LLM呼び出し<br/>（リトライ付き）]
    
    CallLLM --> ParseResponse[レスポンス解析<br/>正規表現パターン<br/>マッチング]
    
    ParseResponse --> ExtractSinks[シンク情報抽出<br/>・function<br/>・param_index<br/>・reason]
    
    ExtractSinks --> RecordTime[解析時間記録]
    
    RecordTime --> NextFunc[次の外部関数]
    NextFunc --> MoreFuncs{他の関数<br/>ある?}
    MoreFuncs -->|Yes| AnalyzeLoop
    MoreFuncs -->|No| Dedup
    
    Dedup[重複排除<br/>&#40;name, param_index&#41;で<br/>ユニーク化]
    
    Dedup --> CollectStats[統計情報収集]
    
    CollectStats --> CheckTokens{トークン追跡<br/>有効?}
    CheckTokens -->|Yes| GetTokenStats[トークン使用量<br/>取得]
    CheckTokens -->|No| SaveResults
    
    GetTokenStats --> SaveResults[結果保存<br/>sinks.json]
    
    SaveResults --> End([終了])
    
    style LoadPhase12 fill:#e1f5fe
    style InitRAGClient fill:#fff3e0
    style CallLLM fill:#ffebee
    style SaveResults fill:#c8e6c9
```

## Phase 4: 候補フロー生成

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadData[必要データ読み込み<br/>・ta_sinks.json<br/>・ta_phase12.json<br/>・compile_commands.json]
    
    LoadData --> ExtractMacros[phase12から<br/>マクロ情報抽出]
    
    ExtractMacros --> CheckDebugMacros{デバッグマクロ<br/>を含める?}
    CheckDebugMacros -->|No| FilterMacros[デバッグマクロ除外<br/>・MSG系パターン<br/>・trace.h定義]
    CheckDebugMacros -->|Yes| KeepAllMacros[全マクロ保持]
    
    FilterMacros --> ParseSources
    KeepAllMacros --> ParseSources[全ソースファイル<br/>パース]
    
    ParseSources --> ParseLoop[各ソースファイル<br/>処理]
    ParseLoop --> AdjustArgs[コンパイル引数調整<br/>・不要オプション除去<br/>・インクルードパス追加]
    
    AdjustArgs --> BuildAST[libclangで<br/>AST構築]
    
    BuildAST --> NextSource{次のソース<br/>ある?}
    NextSource -->|Yes| ParseLoop
    NextSource -->|No| BuildCallGraph
    
    BuildCallGraph[コールグラフ構築]
    BuildCallGraph --> CollectFuncDefs[関数定義収集<br/>・位置情報<br/>・範囲情報]
    
    CollectFuncDefs --> CollectCallEdges[呼び出しエッジ収集<br/>・caller/callee<br/>・呼び出し行番号]
    
    CollectCallEdges --> DetectSinks[シンク呼び出し検出]
    
    DetectSinks --> WalkAST[AST走査]
    WalkAST --> CheckCallExpr{関数呼び出し?}
    
    CheckCallExpr -->|Yes| CheckSinkFunc{シンク関数?}
    CheckCallExpr -->|No| NextNode
    
    CheckSinkFunc -->|Yes| RecordSinkCall[シンク呼び出し記録<br/>・位置情報<br/>・含有関数<br/>・引数情報]
    CheckSinkFunc -->|No| CheckMacroExpand{マクロ展開<br/>trace_printf?}
    
    CheckMacroExpand -->|Yes| RestoreOriginal[元のマクロ名<br/>復元]
    CheckMacroExpand -->|No| NextNode
    
    RestoreOriginal --> RecordSinkCall
    RecordSinkCall --> NextNode[次のノード]
    
    NextNode --> MoreNodes{他のノード<br/>ある?}
    MoreNodes -->|Yes| CheckCallExpr
    MoreNodes -->|No| TraceChains
    
    TraceChains[チェイン追跡]
    TraceChains --> BuildReverseIndex[逆インデックス構築<br/>callee → callers]
    
    BuildReverseIndex --> TraceEachSink[各シンク呼び出し<br/>を追跡]
    
    TraceEachSink --> FindContaining[シンク含有関数<br/>特定]
    
    FindContaining --> TraceBackward[逆方向追跡<br/>（再帰的）]
    
    TraceBackward --> ReachSource{ソース関数<br/>到達?}
    ReachSource -->|Yes| RecordPath[パス記録]
    ReachSource -->|No| CheckCallers{呼び出し元<br/>ある?}
    
    CheckCallers -->|Yes| TraceBackward
    CheckCallers -->|No| DiscardPath[パス破棄]
    
    RecordPath --> ConvertToFlow[フローに変換<br/>・関数チェイン<br/>・行番号リスト]
    DiscardPath --> NextSinkCall
    
    ConvertToFlow --> NextSinkCall[次のシンク]
    NextSinkCall --> MoreSinks{他のシンク<br/>ある?}
    MoreSinks -->|Yes| TraceEachSink
    MoreSinks -->|No| OptimizeFlows
    
    OptimizeFlows[フロー最適化]
    OptimizeFlows --> MergeParams[同一シンク・同一チェインの<br/>param_indexマージ]
    
    MergeParams --> RemoveDups[重複除去]
    
    RemoveDups --> RemoveSubchains[サブチェイン除去<br/>（同一行のみ）]
    
    RemoveSubchains --> MergeSameLine[同一関数内の<br/>複数行シンクマージ]
    
    MergeSameLine --> SaveResults[結果保存<br/>candidate_flows.json]
    
    SaveResults --> End([終了])
    
    style LoadData fill:#e1f5fe
    style BuildCallGraph fill:#fff3e0
    style DetectSinks fill:#f3e5f5
    style TraceChains fill:#fce4ec
    style OptimizeFlows fill:#e8f5e9
    style SaveResults fill:#c8e6c9
```

## Phase 5: テイント解析と脆弱性検査

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadInputs[入力データ読み込み<br/>・candidate_flows.json<br/>・phase12.json<br/>・設定パラメータ]
    
    LoadInputs --> InitConfig[解析設定初期化<br/>・モード決定<br/>・RAG設定<br/>・JSONリトライ戦略]
    
    InitConfig --> CheckMode{解析モード?}
    
    CheckMode -->|hybrid| InitHybrid[Hybridモード初期化<br/>・DITINGルール読込<br/>・CodeQLルール読込]
    CheckMode -->|llm_only| InitLLMOnly[LLM-onlyモード初期化<br/>・CodeQLヒントのみ]
    
    InitHybrid --> CheckRAG1{RAG有効?}
    InitLLMOnly --> CheckRAG2{RAG有効?}
    
    CheckRAG1 -->|Yes| SetupHybridRAG[Hybrid+RAG設定<br/>・RAGクライアント初期化<br/>・ベクトルストア構築]
    CheckRAG1 -->|No| SetupHybridNoRAG[Hybrid設定<br/>・ルールのみ使用]
    
    CheckRAG2 -->|Yes| SetupLLMRAG[LLM+RAG設定<br/>・RAGクライアント初期化]
    CheckRAG2 -->|No| SetupLLMNoRAG[LLM-only設定<br/>・最小構成]
    
    SetupHybridRAG --> GeneratePrompt
    SetupHybridNoRAG --> GeneratePrompt
    SetupLLMRAG --> GeneratePrompt
    SetupLLMNoRAG --> GeneratePrompt
    
    GeneratePrompt[システムプロンプト生成<br/>・テンプレート読込<br/>・プレースホルダー置換]
    
    GeneratePrompt --> InitComponents[コンポーネント初期化<br/>・CodeExtractor<br/>・VulnerabilityParser<br/>・TokenTrackingClient]
    
    InitComponents --> InitAnalyzer[TaintAnalyzer初期化<br/>・PrefixCache<br/>・LLMHandler<br/>・ConsistencyChecker]
    
    InitAnalyzer --> FlowLoop[各フローを解析]
    
    FlowLoop --> ExtractFlowInfo[フロー情報抽出<br/>・function_chain<br/>・function_call_line<br/>・vd（脆弱性記述）]
    
    ExtractFlowInfo --> CheckCache{キャッシュ<br/>チェック?}
    
    CheckCache -->|Hit| RestoreCache[キャッシュ状態復元<br/>・会話履歴<br/>・解析結果]
    CheckCache -->|Miss| StartNew[新規解析開始]
    
    RestoreCache --> AnalyzeRemaining
    StartNew --> AnalyzeFirst
    
    AnalyzeFirst[最初の関数から解析]
    AnalyzeRemaining[残りの関数を解析]
    
    AnalyzeFirst --> FunctionLoop
    AnalyzeRemaining --> FunctionLoop
    
    FunctionLoop[関数解析ループ]
    FunctionLoop --> ExtractCode[関数コード抽出<br/>・行番号付加<br/>・コメント除去]
    
    ExtractCode --> BuildContext[呼び出しコンテキスト構築<br/>・caller情報<br/>・call_line情報]
    
    BuildContext --> GenerateFuncPrompt[関数プロンプト生成<br/>・start/middle/end判定<br/>・RAGコンテキスト追加]
    
    GenerateFuncPrompt --> CallLLM[LLM呼び出し<br/>（リトライ付き）]
    
    CallLLM --> CheckJSON{JSON解析<br/>成功?}
    
    CheckJSON -->|No| RetryJSON{リトライ<br/>戦略?}
    RetryJSON -->|smart| SmartRetry[条件付きリトライ<br/>・重要関数優先<br/>・JSON痕跡確認]
    RetryJSON -->|aggressive| AggressiveRetry[常にリトライ]
    RetryJSON -->|none| AcceptFailure[失敗を受入]
    
    SmartRetry --> GenerateCorrection[JSON修正プロンプト生成]
    AggressiveRetry --> GenerateCorrection
    GenerateCorrection --> CallLLM
    
    CheckJSON -->|Yes| ParseResponse[レスポンス解析<br/>・テイント状態抽出<br/>・リスク指標抽出]
    AcceptFailure --> ParseResponse
    
    ParseResponse --> ExtractFindings[FINDINGS抽出<br/>・インライン検出<br/>・rule_matches処理]
    
    ExtractFindings --> UpdateCache{キャッシュ<br/>更新?}
    
    UpdateCache -->|Yes| SavePrefix[接頭辞キャッシュ保存<br/>・解析状態<br/>・会話履歴]
    UpdateCache -->|No| NextFunc
    
    SavePrefix --> NextFunc[次の関数へ]
    
    NextFunc --> MoreFuncs{他の関数<br/>ある?}
    MoreFuncs -->|Yes| FunctionLoop
    MoreFuncs -->|No| VulnAnalysis
    
    VulnAnalysis[脆弱性判定フェーズ]
    VulnAnalysis --> GenerateEndPrompt[最終プロンプト生成]
    
    GenerateEndPrompt --> CallLLMFinal[LLM最終判定]
    
    CallLLMFinal --> ParseVuln[脆弱性判定解析<br/>・vulnerability_found<br/>・severity抽出]
    
    ParseVuln --> ExtractEndFindings[END_FINDINGS抽出<br/>（拡張抽出）]
    
    ExtractEndFindings --> CheckEndFindings{END_FINDINGS<br/>あり?}
    
    CheckEndFindings -->|No| RecoveryAttempt[救済抽出試行<br/>・柔軟パターン<br/>・LLM再要求]
    CheckEndFindings -->|Yes| ConsistencyCheck1
    
    RecoveryAttempt --> ConsistencyCheck1[整合性チェック1:<br/>テイントフロー検証]
    
    ConsistencyCheck1 --> ValidTaint{有効な<br/>REE→sink?}
    
    ValidTaint -->|No| Reevaluate[再評価<br/>・降格判定<br/>・理由記録]
    ValidTaint -->|Yes| ConsistencyCheck2
    
    Reevaluate --> ConsistencyCheck2[整合性チェック2:<br/>Findings一貫性]
    
    ConsistencyCheck2 --> CheckFindings{Findings<br/>一貫?}
    
    CheckFindings -->|No| AdjustFindings[Findings調整<br/>・誤検出除外<br/>・救済抽出]
    CheckFindings -->|Yes| StoreResult
    
    AdjustFindings --> CheckCrypto{Crypto API<br/>のみ?}
    
    CheckCrypto -->|Yes| CheckDangerous{危険シンク<br/>あり?}
    CheckCrypto -->|No| StoreResult
    
    CheckDangerous -->|No| DowngradeVuln[脆弱性降格<br/>・理由: crypto_only]
    CheckDangerous -->|Yes| StoreResult
    
    DowngradeVuln --> StoreResult[結果保存]
    
    StoreResult --> NextFlow[次のフロー]
    NextFlow --> MoreFlows{他のフロー<br/>ある?}
    MoreFlows -->|Yes| FlowLoop
    MoreFlows -->|No| MergeFindings
    
    MergeFindings[Findingsマージ処理]
    MergeFindings --> GroupFindings[グループ化<br/>・複合キー生成<br/>・近似判定]
    
    GroupFindings --> PrioritySelect[優先順位選択<br/>・end > middle > start<br/>・refs記録]
    
    PrioritySelect --> DeduplicateID[ID重複除去<br/>・完全一致統合]
    
    DeduplicateID --> GenerateReport[レポート生成]
    
    GenerateReport --> SaveJSON[JSON出力<br/>・vulnerabilities<br/>・inline_findings<br/>・statistics]
    
    SaveJSON --> CheckSummary{サマリー<br/>生成?}
    
    CheckSummary -->|Yes| GenerateMD[Markdownレポート生成<br/>・脆弱性サマリー<br/>・Findingsサマリー]
    CheckSummary -->|No| DisplayStats
    
    GenerateMD --> DisplayStats[統計表示<br/>・解析時間<br/>・トークン使用量<br/>・キャッシュ統計]
    
    DisplayStats --> End([終了])
    
    style InitConfig fill:#e1f5fe
    style InitAnalyzer fill:#fff3e0
    style FunctionLoop fill:#f3e5f5
    style VulnAnalysis fill:#fce4ec
    style MergeFindings fill:#e8f5e9
    style GenerateReport fill:#c8e6c9
```

### サブプロセス詳細

#### JSONリトライメカニズム
```mermaid
graph LR
    JSONFail[JSON解析失敗] --> CheckStrategy{戦略確認}
    CheckStrategy -->|smart| CheckImportance[重要度判定<br/>・最終関数?<br/>・エントリ?]
    CheckStrategy -->|aggressive| AlwaysRetry[常にリトライ]
    CheckStrategy -->|none| NoRetry[リトライなし]
    
    CheckImportance --> HasJSONTrace{JSON痕跡<br/>あり?}
    HasJSONTrace -->|Yes| DoRetry[リトライ実行]
    HasJSONTrace -->|No| CheckPosition{重要位置?}
    CheckPosition -->|Yes| DoRetry
    CheckPosition -->|No| NoRetry
    
    AlwaysRetry --> DoRetry
    DoRetry --> CreatePrompt[修正プロンプト生成]
    CreatePrompt --> Attempt1{試行1}
    Attempt1 -->|失敗| Attempt2{試行2}
    Attempt2 -->|失敗| Attempt3{試行3}
    Attempt3 -->|失敗| GiveUp[諦める]
```

#### 整合性チェックプロセス
```mermaid
graph TB
    Input[解析結果] --> TaintCheck[テイントフロー検証]
    TaintCheck --> HasPath{REE→Sink<br/>パスあり?}
    
    HasPath -->|No| CheckVuln{脆弱性<br/>フラグ?}
    HasPath -->|Yes| FindingsCheck
    
    CheckVuln -->|Yes| Downgrade[降格処理<br/>・suspected設定]
    CheckVuln -->|No| FindingsCheck
    
    Downgrade --> FindingsCheck[Findings一貫性確認]
    
    FindingsCheck --> VulnYes{vuln=yes?}
    VulnYes -->|Yes| HasFindings{Findings<br/>あり?}
    VulnYes -->|No| CheckFindings2{Findings<br/>あり?}
    
    HasFindings -->|No| SalvageAttempt[救済抽出<br/>・柔軟パターン<br/>・空構造検出]
    HasFindings -->|Yes| ValidateFindings
    
    CheckFindings2 -->|Yes| UpgradeVuln[脆弱性昇格]
    CheckFindings2 -->|No| Output
    
    SalvageAttempt --> FoundFindings{救済<br/>成功?}
    FoundFindings -->|Yes| ValidateFindings[Findings検証]
    FoundFindings -->|No| MarkSuspected[suspected設定]
    
    ValidateFindings --> RemoveFP[誤検出除去<br/>・プレースホルダー<br/>・line=0]
    
    RemoveFP --> Output[調整済み結果]
    UpgradeVuln --> Output
    MarkSuspected --> Output
```

####　簡易レポート生成 - Phase 5
```mermaid
graph TB
    Start([開始]) --> LoadResults[解析結果読み込み<br/>・vulnerabilities<br/>・inline_findings<br/>・statistics]
    
    LoadResults --> CheckFormat{出力形式?}
    
    CheckFormat -->|JSON| GenerateJSON[JSON生成<br/>・構造化データ<br/>・メタデータ追加]
    CheckFormat -->|Markdown| GenerateMD[Markdown生成<br/>・人間可読形式<br/>・セクション分割]
    CheckFormat -->|CSV| GenerateCSV[CSV生成<br/>・表形式<br/>・Excel互換]
    CheckFormat -->|All| GenerateAll[全形式生成]
    
    GenerateJSON --> AddMetadata[メタデータ追加<br/>・生成時刻<br/>・バージョン<br/>・設定情報]
    
    GenerateMD --> CreateSections[セクション作成<br/>・統計サマリー<br/>・脆弱性詳細<br/>・Findings一覧]
    
    CreateSections --> FormatVulns[脆弱性整形<br/>・チェイン表示<br/>・シンク情報<br/>・重要度]
    
    FormatVulns --> FormatFindings[Findings整形<br/>・カテゴリ別<br/>・ファイル別<br/>・関数別]
    
    GenerateCSV --> CreateHeaders[ヘッダー作成<br/>・標準フィールド]
    CreateHeaders --> WriteRows[行データ書き込み]
    
    GenerateAll --> ParallelGen[並列生成<br/>・JSON<br/>・Markdown<br/>・CSV]
    
    AddMetadata --> SaveJSON[JSON保存]
    FormatFindings --> SaveMD[Markdown保存]
    WriteRows --> SaveCSV[CSV保存]
    ParallelGen --> SaveAll[全ファイル保存]
    
    SaveJSON --> GenerateStats
    SaveMD --> GenerateStats
    SaveCSV --> GenerateStats
    SaveAll --> GenerateStats
    
    GenerateStats[統計レポート生成]
    GenerateStats --> AnalysisTime[解析時間統計<br/>・総時間<br/>・フロー平均<br/>・関数平均]
    
    AnalysisTime --> TokenStats[トークン統計<br/>・総使用量<br/>・入力/出力<br/>・API呼び出し数]
    
    TokenStats --> CacheStats[キャッシュ統計<br/>・ヒット率<br/>・削減量<br/>・効率性]
    
    CacheStats --> FindingsStats[Findings統計<br/>・総数<br/>・カテゴリ別<br/>・重複除去数]
    
    FindingsStats --> ConsistencyStats[整合性統計<br/>・再評価数<br/>・降格数<br/>・救済数]
    
    ConsistencyStats --> CreateSummary[サマリー作成<br/>・主要指標<br/>・推奨事項<br/>・次のステップ]
    
    CreateSummary --> DisplayResults[結果表示<br/>・コンソール出力<br/>・ファイルパス<br/>・実行時間]
    
    DisplayResults --> End([終了])
    
    style LoadResults fill:#e1f5fe
    style GenerateStats fill:#fff3e0
    style CreateSummary fill:#e8f5e9
```
#### 脆弱性レポート構造
```mermaid
graph TB
    Report[レポート] --> Header[ヘッダー<br/>・タイトル<br/>・生成日時<br/>・バージョン]
    
    Report --> Statistics[統計セクション<br/>・解析モード<br/>・実行時間<br/>・検出数]
    
    Report --> Vulnerabilities[脆弱性セクション]
    Vulnerabilities --> VulnItem[各脆弱性]
    
    VulnItem --> Chain[チェイン情報<br/>・関数フロー<br/>・呼び出し順序]
    
    VulnItem --> SinkInfo[シンク情報<br/>・関数名<br/>・ファイル<br/>・行番号]
    
    VulnItem --> TaintFlow[テイントフロー<br/>・各ステップ<br/>・伝播状態<br/>・検証結果]
    
    VulnItem --> Evidence[証拠<br/>・コード片<br/>・rule_matches<br/>・FINDINGS]
    
    Report --> FindingsList[Findings一覧]
    FindingsList --> ByCategory[カテゴリ別<br/>・UO<br/>・WIV<br/>・SMO]
    
    FindingsList --> ByFile[ファイル別<br/>・グループ化<br/>・行番号順]
    
    FindingsList --> ByPhase[フェーズ別<br/>・start<br/>・middle<br/>・end]
    
    Report --> Recommendations[推奨事項<br/>・修正優先度<br/>・対策方法<br/>・参考情報]
```
#### 統計ダッシュボード
```mermaid
graph LR
    Stats[統計情報] --> Performance[パフォーマンス]
    Performance --> Time[時間<br/>・総時間<br/>・平均時間]
    Performance --> Tokens[トークン<br/>・使用量<br/>・コスト推定]
    
    Stats --> Quality[品質指標]
    Quality --> Coverage[カバレッジ<br/>・解析フロー数<br/>・成功率]
    Quality --> Accuracy[精度<br/>・整合性<br/>・降格率]
    
    Stats --> Efficiency[効率性]
    Efficiency --> Cache[キャッシュ<br/>・ヒット率<br/>・削減効果]
    Efficiency --> Retry[リトライ<br/>・成功率<br/>・回数]
```

## Phase 6: HTMLレポート生成

### 処理フロー

```mermaid
graph TB
    Start([開始]) --> LoadInputs[入力ファイル読込<br/>・vulnerabilities.json<br/>・phase12.json<br/>・sinks.json 任意]
    
    LoadInputs --> CheckLogFile{ログファイル<br/>存在?}
    
    CheckLogFile -->|Yes| ParseLog[ログ解析<br/>taint_analysis_log.txt]
    CheckLogFile -->|No| EmptyConv[空の対話履歴]
    
    ParseLog --> ExtractConv[対話履歴抽出<br/>・チェーン名検出<br/>・プロンプト/応答<br/>・整合性メッセージ]
    EmptyConv --> ExtractConv
    
    ExtractConv --> LoadFlows{candidate_flows<br/>存在?}
    
    LoadFlows -->|Yes| ExtractAllChains[全チェーン抽出<br/>・解析済みチェーン<br/>・未解析チェーン]
    LoadFlows -->|No| UseVulnChains[脆弱性チェーンのみ使用]
    
    ExtractAllChains --> CalculateStats
    UseVulnChains --> CalculateStats
    
    CalculateStats[統計情報計算<br/>・チェーン数<br/>・関数数<br/>・LLM呼び出し数]
    
    CalculateStats --> MapVulnToChain[脆弱性マッピング<br/>チェーン名→脆弱性情報]
    
    MapVulnToChain --> GenerateChainHTML[チェーンHTML生成（ループ）]
    
    GenerateChainHTML --> CheckConversation{対話履歴<br/>あり?}
    
    CheckConversation -->|Yes| FormatMessages[メッセージ整形<br/>・JSON検出/整形<br/>・コードブロック処理<br/>・HTMLエスケープ]
    CheckConversation -->|No| NoAnalysisHTML[未解析表示]
    
    FormatMessages --> CheckVuln{脆弱性<br/>あり?}
    NoAnalysisHTML --> CheckVuln
    
    CheckVuln -->|Yes| AddVulnInfo[脆弱性情報追加<br/>・タイプ<br/>・深刻度<br/>・説明]
    CheckVuln -->|No| SafeStatus[安全ステータス]
    
    AddVulnInfo --> CreateChainItem
    SafeStatus --> CreateChainItem
    
    CreateChainItem[チェーン要素作成<br/>・フロー表示<br/>・対話履歴<br/>・折りたたみ機能]
    
    CreateChainItem --> MoreChains{他のチェーン<br/>ある?}
    MoreChains -->|Yes| GenerateChainHTML
    MoreChains -->|No| GenerateSections
    
    GenerateSections[セクション生成]
    
    GenerateSections --> GenTimeline[実行タイムライン生成<br/>・Phase3時間<br/>・Phase5時間<br/>・プログレスバー]
    
    GenTimeline --> GenTokenUsage[トークン使用量生成<br/>・シンク特定<br/>・テイント解析<br/>・合計統計]
    
    GenTokenUsage --> GenSinksSummary[シンクサマリー生成<br/>・特定シンク一覧<br/>・判定方法（LLM/Rule）<br/>・パラメータ情報]
    
    GenSinksSummary --> GenVulnDetails[脆弱性詳細生成<br/>・検出脆弱性リスト<br/>・深刻度表示<br/>・場所情報]
    
    GenVulnDetails --> GenFindings[Findings生成<br/>・インライン検出<br/>・カテゴリ分類<br/>・ルールマッチ]
    
    GenFindings --> LoadTemplate[HTMLテンプレート読込<br/>・CSS/JS組み込み<br/>・プレースホルダー定義]
    
    LoadTemplate --> FillTemplate[テンプレート埋込<br/>・プロジェクト情報<br/>・統計データ<br/>・各セクションHTML]
    
    FillTemplate --> HandlePlaceholder{プレースホルダー<br/>エラー?}
    
    HandlePlaceholder -->|Yes| AddDefault[デフォルト値設定<br/>・N/A埋込<br/>・再試行]
    HandlePlaceholder -->|No| GenerateHTML
    
    AddDefault --> RetryFill[埋込再試行]
    RetryFill --> CheckRetry{成功?}
    
    CheckRetry -->|Yes| GenerateHTML
    CheckRetry -->|No| MinimalHTML[最小HTML生成<br/>・エラーメッセージ]
    
    GenerateHTML[完全HTML生成]
    
    GenerateHTML --> SaveHTML[HTMLファイル保存]
    MinimalHTML --> SaveHTML
    
    SaveHTML --> AddAssets[アセット処理<br/>・styles.css<br/>・script.js<br/>・埋込/外部参照]
    
    AddAssets --> DisplaySummary[サマリー表示<br/>・保存先パス<br/>・検出数<br/>・実行時間]
    
    DisplaySummary --> End([終了])
    
    style LoadInputs fill:#e1f5fe
    style ParseLog fill:#fff3e0
    style GenerateSections fill:#f3e5f5
    style LoadTemplate fill:#fce4ec
    style SaveHTML fill:#e8f5e9
```

### サブプロセス詳細

#### ログ解析プロセス
```mermaid
graph TB
    LogFile[taint_analysis_log.txt] --> ReadContent[ファイル読込<br/>UTF-8/ignore errors]
    
    ReadContent --> ScanLines[行スキャン]
    
    ScanLines --> DetectChain{チェーン開始<br/>検出?}
    
    DetectChain -->|"Analyzing chain:"| SavePrevious[前チェーン保存]
    DetectChain -->|No| CheckSection
    
    SavePrevious --> ExtractChainName[チェーン名抽出<br/>正規表現マッチ]
    
    ExtractChainName --> InitChain[チェーン初期化<br/>・会話リスト<br/>・セクション情報]
    
    CheckSection[セクション判定]
    CheckSection --> IsFuncSection{Function<br/>セクション?}
    CheckSection --> IsVulnSection{Vulnerability<br/>セクション?}
    CheckSection --> IsPrompt{### Prompt?}
    CheckSection --> IsResponse{### Response?}
    
    IsFuncSection -->|Yes| SetFuncContext[関数コンテキスト設定]
    IsVulnSection -->|Yes| SetVulnContext[脆弱性コンテキスト設定]
    
    IsPrompt -->|Yes| CollectPrompt[プロンプト収集<br/>・複数行対応<br/>・終了条件判定]
    
    CollectPrompt --> AddUserMsg[userメッセージ追加]
    
    IsResponse -->|Yes| CollectResponse[レスポンス収集<br/>・複数行対応<br/>・セクション境界]
    
    CollectResponse --> AddAssistantMsg[assistantメッセージ追加]
    
    SetFuncContext --> NextLine
    SetVulnContext --> NextLine
    AddUserMsg --> NextLine
    AddAssistantMsg --> NextLine
    
    NextLine[次の行へ] --> MoreLines{他の行<br/>ある?}
    MoreLines -->|Yes| ScanLines
    MoreLines -->|No| SaveFinal[最終チェーン保存]
    
    SaveFinal --> ReturnConv[対話履歴辞書返却]
```

#### HTMLフォーマット処理
```mermaid
graph TB
    Message[メッセージ内容] --> EscapeHTML[HTMLエスケープ]
    
    EscapeHTML --> DetectJSON{JSON検出?}
    
    DetectJSON -->|Yes| ParseJSON[JSON解析]
    DetectJSON -->|No| DetectCode
    
    ParseJSON --> FormatJSON[JSON整形<br/>・インデント<br/>・構文ハイライト]
    
    FormatJSON --> WrapPre[preタグでラップ]
    
    DetectCode[コードブロック検出]
    DetectCode --> HasCodeBlock{```あり?}
    
    HasCodeBlock -->|Yes| ExtractCode[コード抽出]
    HasCodeBlock -->|No| DetectInline
    
    ExtractCode --> ApplyHighlight[構文ハイライト<br/>・言語判定<br/>・色付け]
    
    DetectInline[インラインコード検出]
    DetectInline --> HasBacktick{`あり?}
    
    HasBacktick -->|Yes| WrapCode[codeタグでラップ]
    HasBacktick -->|No| ProcessNewlines
    
    WrapPre --> MergeContent
    ApplyHighlight --> MergeContent
    WrapCode --> MergeContent
    
    ProcessNewlines[改行処理<br/>brタグ変換]
    
    ProcessNewlines --> MergeContent[コンテンツ統合]
    
    MergeContent --> ReturnHTML[HTML文字列返却]
```

#### 統計計算プロセス
```mermaid
graph TB
    Input[入力データ] --> CountChains[チェーン数計算]
    
    CountChains --> FromConv{対話履歴<br/>あり?}
    
    FromConv -->|Yes| UseConvCount[対話履歴数使用]
    FromConv -->|No| UseVulnCount[脆弱性数使用]
    
    UseConvCount --> ExtractUnique
    UseVulnCount --> ExtractUnique
    
    ExtractUnique[ユニークチェーン抽出]
    ExtractUnique --> FromVulns[脆弱性から抽出]
    ExtractUnique --> FromConvs[対話履歴から抽出]
    
    FromVulns --> MergeUnique[重複除去<br/>Set使用]
    FromConvs --> MergeUnique
    
    MergeUnique --> CountFunctions[関数数計算<br/>チェーン分割]
    
    CountFunctions --> GetLLMCalls[LLM呼び出し数取得]
    
    GetLLMCalls --> FromStats{統計情報<br/>あり?}
    
    FromStats -->|Yes| UseStatCalls[統計値使用]
    FromStats -->|No| EstimateFromTokens[トークン数から推定]
    
    EstimateFromTokens --> CheckSinks{シンクデータ<br/>あり?}
    
    CheckSinks -->|Yes| AddSinkCalls[シンク呼び出し追加]
    CheckSinks -->|No| FinalStats
    
    UseStatCalls --> FinalStats
    AddSinkCalls --> FinalStats
    
    FinalStats[最終統計作成]
    FinalStats --> ReturnStats[統計辞書返却]
```

### レポート構成要素

#### 脆弱性レポート構造
```mermaid
graph TB
    Report[レポート] --> Header[ヘッダー<br/>・タイトル<br/>・生成日時<br/>・バージョン]
    
    Report --> Statistics[統計セクション<br/>・解析モード<br/>・実行時間<br/>・検出数]
    
    Report --> Vulnerabilities[脆弱性セクション]
    Vulnerabilities --> VulnItem[各脆弱性]
    
    VulnItem --> Chain[チェイン情報<br/>・関数フロー<br/>・呼び出し順序]
    
    VulnItem --> SinkInfo[シンク情報<br/>・関数名<br/>・ファイル<br/>・行番号]
    
    VulnItem --> TaintFlow[テイントフロー<br/>・各ステップ<br/>・伝播状態<br/>・検証結果]
    
    VulnItem --> Evidence[証拠<br/>・コード片<br/>・rule_matches<br/>・FINDINGS]
    
    Report --> FindingsList[Findings一覧]
    FindingsList --> ByCategory[カテゴリ別<br/>・UO<br/>・WIV<br/>・SMO]
    
    FindingsList --> ByFile[ファイル別<br/>・グループ化<br/>・行番号順]
    
    FindingsList --> ByPhase[フェーズ別<br/>・start<br/>・middle<br/>・end]
    
    Report --> Recommendations[推奨事項<br/>・修正優先度<br/>・対策方法<br/>・参考情報]
```

#### 統計ダッシュボード
```mermaid
graph LR
    Stats[統計情報] --> Performance[パフォーマンス]
    Performance --> Time[時間<br/>・総時間<br/>・平均時間]
    Performance --> Tokens[トークン<br/>・使用量<br/>・コスト推定]
    
    Stats --> Quality[品質指標]
    Quality --> Coverage[カバレッジ<br/>・解析フロー数<br/>・成功率]
    Quality --> Accuracy[精度<br/>・整合性<br/>・降格率]
    
    Stats --> Efficiency[効率性]
    Efficiency --> Cache[キャッシュ<br/>・ヒット率<br/>・削減効果]
    Efficiency --> Retry[リトライ<br/>・成功率<br/>・回数]
```

# 番外編
## RAG + LLM 処理フロー

### 1. 初期化フェーズ

```mermaid
graph TB
    Start([開始]) --> InitRAG[TEERAGClient初期化]
    
    InitRAG --> InitComponents[コンポーネント初期化]
    InitComponents --> InitLoader[DocumentLoader初期化<br/>・PDF格納ディレクトリ設定]
    InitComponents --> InitProcessor[TextProcessor初期化<br/>・チャンクサイズ: 1000<br/>・オーバーラップ: 200]
    InitComponents --> InitStore[VectorStore初期化<br/>・埋め込みモデル設定<br/>・永続化ディレクトリ設定]
    InitComponents --> InitRetriever[Retriever初期化<br/>・検索戦略設定]
    
    InitLoader --> CheckIndex
    InitProcessor --> CheckIndex
    InitStore --> CheckIndex
    InitRetriever --> CheckIndex
    
    CheckIndex{既存インデックス<br/>存在?}
    CheckIndex -->|Yes| LoadIndex[インデックス読み込み<br/>・メタデータ復元<br/>・統計情報復元]
    CheckIndex -->|No| WaitBuild[build_index&#40;&#41;<br/>実行待機]
    
    LoadIndex --> Ready([準備完了])
    WaitBuild --> Ready
    
    style InitRAG fill:#e1f5fe
    style Ready fill:#c8e6c9
```

### 2. インデックス構築フェーズ

```mermaid
graph TB
    BuildStart([build_index開始]) --> LoadPDFs[PDFドキュメント読み込み]
    
    LoadPDFs --> ProcessPDF[各PDFファイル処理]
    ProcessPDF --> TryPDFPlumber{pdfplumber<br/>試行}
    
    TryPDFPlumber -->|成功| ExtractText1[テキスト抽出]
    TryPDFPlumber -->|失敗| TryPyPDF2{PyPDF2<br/>試行}
    
    TryPyPDF2 -->|成功| ExtractText2[テキスト抽出]
    TryPyPDF2 -->|失敗| SkipFile[ファイルスキップ]
    
    ExtractText1 --> AddMetadata[メタデータ付与<br/>・ページ番号<br/>・ドキュメントタイプ<br/>・ファイル名]
    ExtractText2 --> AddMetadata
    
    AddMetadata --> ExtractAPIs[API関数情報抽出<br/>・TEE_*<br/>・TEEC_*<br/>・TA_*]
    
    ExtractAPIs --> NextPDF{次のPDF<br/>ある?}
    SkipFile --> NextPDF
    NextPDF -->|Yes| ProcessPDF
    NextPDF -->|No| TextProcessing
    
    TextProcessing[テキスト処理開始]
    TextProcessing --> CleanText[テキストクリーニング<br/>・空白正規化<br/>・改行正規化<br/>・不要記号除去]
    
    CleanText --> CheckAPI{API定義<br/>含む?}
    
    CheckAPI -->|Yes| ExtractAPIChunks[API定義チャンク抽出<br/>・個別チャンク化<br/>・パラメータ解析<br/>・戻り値抽出]
    CheckAPI -->|No| RegularChunks
    
    ExtractAPIChunks --> RegularChunks[通常チャンク分割<br/>・1000文字単位<br/>・200文字オーバーラップ]
    
    RegularChunks --> ChromaNormalize[ChromaDB正規化<br/>・メタデータ型変換<br/>・リスト→文字列<br/>・辞書→フラット化]
    
    ChromaNormalize --> RemoveDuplicates[重複チャンク除去]
    
    RemoveDuplicates --> CreateVectors[ベクトル生成<br/>・埋め込みモデル適用<br/>・sentence-transformers]
    
    CreateVectors --> StoreVectors{ストアタイプ?}
    
    StoreVectors -->|ChromaDB| SaveChroma[ChromaDB保存<br/>・自動永続化]
    StoreVectors -->|FAISS| SaveFAISS[FAISS保存<br/>・手動永続化]
    
    SaveChroma --> BuildMetaIndex
    SaveFAISS --> BuildMetaIndex
    
    BuildMetaIndex[メタデータインデックス構築<br/>・API関数インデックス<br/>・ドキュメントタイプ<br/>・セクション情報]
    
    BuildMetaIndex --> SaveCache[キャッシュ保存<br/>・統計情報<br/>・インデックス作成時刻]
    
    SaveCache --> BuildEnd([構築完了])
    
    style BuildStart fill:#e1f5fe
    style TextProcessing fill:#fff3e0
    style CreateVectors fill:#f3e5f5
    style BuildEnd fill:#c8e6c9
```

### 3. RAG検索フェーズ

```mermaid
graph TB
    SearchStart([検索開始]) --> CheckSearchType{検索タイプ?}
    
    CheckSearchType -->|シンク解析| SinkAnalysis[search_for_sink_analysis]
    CheckSearchType -->|脆弱性解析| VulnAnalysis[search_for_vulnerability_analysis]
    
    %% シンク解析フロー
    SinkAnalysis --> CreateQueries1[検索クエリ生成<br/>・&quot;api_name&quot; function<br/>・api_name parameters<br/>・api_name description]
    
    CreateQueries1 --> RetrieveSink[retrieve_for_sink_identification]
    RetrieveSink --> SearchByAPI[API優先検索<br/>・search_by_api呼び出し<br/>・メタデータフィルタ]
    
    SearchByAPI --> SecurityKeywords[セキュリティキーワード検索<br/>・security<br/>・vulnerability<br/>・buffer overflow<br/>・validation]
    
    SecurityKeywords --> ScoreDocs1[文書スコアリング<br/>・API定義: +0.5<br/>・セキュリティキーワード: +0.05<br/>・パラメータ記述: +0.1]
    
    ScoreDocs1 --> SortDocs1[スコア降順ソート]
    SortDocs1 --> FilterRegex1[正規表現フィルタ<br/>・api_name完全一致のみ]
    
    FilterRegex1 --> BuildContext1[コンテキスト構築（最大3000文字）]
    BuildContext1 --> APIDef{API定義<br/>あり?}
    
    APIDef -->|Yes| AddAPISection[API定義セクション追加]
    APIDef -->|No| SecuritySection
    
    AddAPISection --> SecuritySection[セキュリティセクション追加]
    SecuritySection --> FormatContext1[コンテキスト整形<br/>・ソース情報付与<br/>・ページ番号付与]
    
    %% 脆弱性解析フロー
    VulnAnalysis --> ExtractFunctions[関数呼び出し抽出<br/>・コードスニペット解析<br/>・TEE関連関数のみ]
    
    ExtractFunctions --> CreateQueries2[複合クエリ生成]
    CreateQueries2 --> Query1[シンク詳細検索<br/>・search_by_api]
    CreateQueries2 --> Query2[パラメータ検証検索<br/>・param validation]
    CreateQueries2 --> Query3[脆弱性パターン検索<br/>・buffer overflow<br/>・integer overflow<br/>・null pointer]
    
    Query1 --> CollectResults
    Query2 --> CollectResults
    Query3 --> CollectResults
    
    CollectResults[結果収集]
    CollectResults --> ScoreDocs2[文書スコアリング<br/>・シンク言及: +0.3<br/>・呼び出し関数: +0.1<br/>・脆弱性キーワード: +0.05<br/>・CWE参照: +0.2]
    
    ScoreDocs2 --> Dedup[重複除去<br/>・ファイル名/ページ番号]
    
    Dedup --> WindowExtract[ウィンドウ抽出<br/>・シンク周辺±500文字]
    
    WindowExtract --> BuildContext2[コンテキスト構築（最大3000文字）]
    BuildContext2 --> SinkInfo{シンク情報<br/>あり?}
    
    SinkInfo -->|Yes| AddSinkSection[シンク情報セクション]
    SinkInfo -->|No| ParamSection
    
    AddSinkSection --> ParamSection[パラメータ検証セクション]
    ParamSection --> VulnPatternSection[脆弱性パターンセクション]
    
    VulnPatternSection --> FormatContext2[コンテキスト整形]
    
    FormatContext1 --> ReturnContext[コンテキスト返却]
    FormatContext2 --> ReturnContext
    
    ReturnContext --> SearchEnd([検索完了])
    
    style SearchStart fill:#e1f5fe
    style SinkAnalysis fill:#fff3e0
    style VulnAnalysis fill:#f3e5f5
    style SearchEnd fill:#c8e6c9
```

### 4. LLM問い合わせフェーズ

```mermaid
graph TB
    LLMStart([LLM処理開始]) --> InitClient[UnifiedLLMClient初期化]
    
    InitClient --> LoadConfig[ConfigManager初期化<br/>・llm_config.json読み込み<br/>・プロバイダー設定確認]
    
    LoadConfig --> CheckProvider{アクティブ<br/>プロバイダー?}
    
    CheckProvider -->|OpenAI| InitOpenAI[OpenAIClient生成]
    CheckProvider -->|Claude| InitClaude[ClaudeClient生成]
    CheckProvider -->|DeepSeek| InitDeepSeek[DeepSeekClient生成]
    CheckProvider -->|Gemini| InitGemini[GeminiClient生成]
    CheckProvider -->|Ollama| InitOllama[LocalLLMClient生成]
    
    InitOpenAI --> BuildPrompt
    InitClaude --> BuildPrompt
    InitDeepSeek --> BuildPrompt
    InitGemini --> BuildPrompt
    InitOllama --> BuildPrompt
    
    BuildPrompt[プロンプト構築]
    BuildPrompt --> SystemPrompt[システムプロンプト]
    BuildPrompt --> RAGContext[RAGコンテキスト挿入]
    BuildPrompt --> UserQuery[ユーザークエリ/コード]
    
    SystemPrompt --> CreateMessages
    RAGContext --> CreateMessages
    UserQuery --> CreateMessages
    
    CreateMessages[メッセージ配列作成<br/>role: system/user/assistant]
    
    CreateMessages --> InitRetry[LLMRetryHandler初期化<br/>・最大リトライ: 3<br/>・基本遅延: 2秒]
    
    InitRetry --> RateLimiter[レート制限待機<br/>・最小間隔: 0.7秒]
    
    RateLimiter --> CallLLM[LLM API呼び出し]
    
    CallLLM --> CheckResponse{レスポンス<br/>検証}
    
    CheckResponse -->|成功| ValidResponse[有効レスポンス]
    CheckResponse -->|空/None| DiagnoseEmpty
    CheckResponse -->|エラー| AnalyzeError
    
    ValidResponse --> ReturnResponse[レスポンス返却]
    
    DiagnoseEmpty[空レスポンス診断]
    DiagnoseEmpty --> ResponseAnalysis[レスポンス分析<br/>・型チェック<br/>・長さ確認<br/>・16進ダンプ]
    DiagnoseEmpty --> PromptAnalysis[プロンプト分析<br/>・文字数<br/>・トークン推定<br/>・特殊文字]
    DiagnoseEmpty --> EnvAnalysis[環境分析<br/>・APIキー確認<br/>・プロバイダー設定<br/>・メモリ使用量]
    DiagnoseEmpty --> APITest[API接続テスト<br/>・簡単なプロンプト送信<br/>・応答時間測定]
    
    ResponseAnalysis --> GenerateDiagnosis
    PromptAnalysis --> GenerateDiagnosis
    EnvAnalysis --> GenerateDiagnosis
    APITest --> GenerateDiagnosis
    
    GenerateDiagnosis[診断レポート生成<br/>・原因リスト<br/>・推奨事項]
    
    AnalyzeError[エラー分析]
    AnalyzeError --> CheckErrorType{エラータイプ?}
    
    CheckErrorType -->|TIMEOUT| TimeoutError[タイムアウト処理]
    CheckErrorType -->|RATE_LIMIT| RateError[レート制限処理]
    CheckErrorType -->|TOKEN_LIMIT| TokenError[トークン制限処理]
    CheckErrorType -->|AUTH_ERROR| AuthError[認証エラー処理]
    CheckErrorType -->|CONTENT_FILTER| ContentError[コンテンツフィルタ処理]
    CheckErrorType -->|その他| UnknownError[不明エラー処理]
    
    GenerateDiagnosis --> CheckRetry
    TimeoutError --> CheckRetry
    RateError --> CheckRetry
    TokenError --> NoRetry
    AuthError --> NoRetry
    ContentError --> NoRetry
    UnknownError --> CheckRetry
    
    CheckRetry{リトライ<br/>判定}
    CheckRetry -->|可能| CalculateDelay[遅延計算<br/>・指数バックオフ<br/>・最大60秒]
    CheckRetry -->|不可| NoRetry
    
    NoRetry[リトライ中止]
    
    CalculateDelay --> WaitDelay[遅延待機]
    WaitDelay --> IncrementAttempt[試行回数+1]
    
    IncrementAttempt --> CheckMaxRetry{最大試行<br/>到達?}
    CheckMaxRetry -->|No| RateLimiter
    CheckMaxRetry -->|Yes| FatalError
    
    NoRetry --> FatalError[致命的エラー処理]
    
    FatalError --> LogError[エラーログ記録<br/>・詳細ログ<br/>・JSON形式<br/>・診断レポート]
    
    LogError --> DisplayError[エラー表示<br/>・エラー履歴<br/>・診断ファイル情報]
    
    DisplayError --> Exit([プログラム終了])
    ReturnResponse --> LLMEnd([LLM処理完了])
    
    style LLMStart fill:#e1f5fe
    style BuildPrompt fill:#fff3e0
    style CallLLM fill:#f3e5f5
    style DiagnoseEmpty fill:#fce4ec
    style FatalError fill:#ffcdd2
    style LLMEnd fill:#c8e6c9
```

### 5. プロバイダー別処理詳細

```mermaid
graph TB
    Provider[プロバイダー処理] --> CheckType{プロバイダー<br/>タイプ?}
    
    CheckType -->|OpenAI系| OpenAIFlow[OpenAI互換処理]
    CheckType -->|Claude| ClaudeFlow[Claude処理]
    CheckType -->|Gemini| GeminiFlow[Gemini処理]
    CheckType -->|Local| LocalFlow[ローカル処理]
    
    %% OpenAI系処理
    OpenAIFlow --> OpenAIClient[OpenAI Client使用]
    OpenAIClient --> CreateCompletion[chat.completions.create&#40;&#41;]
    CreateCompletion --> OpenAIParams[パラメータ設定<br/>・model<br/>・temperature: 0.0<br/>・max_tokens: 4096<br/>・timeout: 60]
    
    %% Claude処理
    ClaudeFlow --> ClaudeClient[Anthropic Client使用]
    ClaudeClient --> ConvertMessages[メッセージ変換<br/>・systemをuserに統合]
    ConvertMessages --> CreateMessage[messages.create&#40;&#41;]
    CreateMessage --> ClaudeParams[パラメータ設定<br/>・model<br/>・temperature: 0.0<br/>・max_tokens: 4096]
    
    %% Gemini処理
    GeminiFlow --> GeminiClient[GenerativeModel使用]
    GeminiClient --> StartChat[start_chat&#40;&#41;初期化]
    StartChat --> MergeSystem[システムメッセージ統合<br/>・最初のuserに結合]
    MergeSystem --> SendMessage[send_message&#40;&#41;]
    SendMessage --> GeminiParams[パラメータ設定<br/>・temperature: 0.0<br/>・max_output_tokens: 8192<br/>・safety_settings]
    
    %% ローカル処理
    LocalFlow --> LocalClient[REST API直接呼び出し]
    LocalClient --> PreparePayload[ペイロード準備<br/>・model<br/>・messages<br/>・stream: false]
    PreparePayload --> PostRequest[POST /api/chat]
    PostRequest --> LocalParams[パラメータ設定<br/>・temperature: 0.0<br/>・num_predict: 4096<br/>・timeout: 120]
    
    OpenAIParams --> ExtractContent
    ClaudeParams --> ExtractContent
    GeminiParams --> ExtractContent
    LocalParams --> ExtractContent
    
    ExtractContent[コンテンツ抽出]
    ExtractContent --> ReturnText[テキスト返却]
    
    style Provider fill:#e1f5fe
    style ExtractContent fill:#c8e6c9
```

### 6. エラー処理とリカバリフロー

```mermaid
graph TB
    ErrorOccur([エラー発生]) --> ErrorAnalyzer[LLMErrorAnalyzer]
    
    ErrorAnalyzer --> CheckException{例外タイプ?}
    
    CheckException -->|HTTPエラー| HTTPAnalysis[HTTP分析<br/>・ステータスコード<br/>・レスポンステキスト]
    CheckException -->|その他| PatternMatch[パターンマッチング]
    
    HTTPAnalysis --> StatusMap{ステータス<br/>コード?}
    
    StatusMap -->|429| CreateRateLimit[RATE_LIMIT生成]
    StatusMap -->|408/504| CreateTimeout[TIMEOUT生成]
    StatusMap -->|401| CreateAuth[AUTH_ERROR生成]
    StatusMap -->|400| Check400{内容確認}
    StatusMap -->|500-503| CreateServer[SERVER_ERROR生成]
    
    Check400 -->|content_filter| CreateFilter[CONTENT_FILTER生成]
    Check400 -->|その他| CreateBadRequest[BAD_REQUEST生成]
    
    PatternMatch --> MatchPatterns{パターン<br/>一致?}
    
    MatchPatterns -->|timeout| CreateTimeout2[TIMEOUT生成]
    MatchPatterns -->|rate/limit| CreateRateLimit2[RATE_LIMIT生成]
    MatchPatterns -->|token/context| CreateTokenLimit[TOKEN_LIMIT生成]
    MatchPatterns -->|filter/blocked| CreateFilter2[CONTENT_FILTER生成]
    MatchPatterns -->|connection| CreateNetwork[NETWORK_ERROR生成]
    MatchPatterns -->|unauthorized| CreateAuth2[AUTH_ERROR生成]
    MatchPatterns -->|なし| CreateUnknown[UNKNOWN_ERROR生成]
    
    CreateRateLimit --> LLMError
    CreateTimeout --> LLMError
    CreateAuth --> LLMError
    CreateFilter --> LLMError
    CreateBadRequest --> LLMError
    CreateServer --> LLMError
    CreateTimeout2 --> LLMError
    CreateRateLimit2 --> LLMError
    CreateTokenLimit --> LLMError
    CreateFilter2 --> LLMError
    CreateNetwork --> LLMError
    CreateAuth2 --> LLMError
    CreateUnknown --> LLMError
    
    LLMError[LLMErrorオブジェクト<br/>・error_type<br/>・message<br/>・details<br/>・timestamp]
    
    LLMError --> ErrorLogger[LLMErrorLogger]
    
    ErrorLogger --> LogDetail[詳細ログ記録<br/>llm_error_details.log]
    ErrorLogger --> LogJSON[JSON記録<br/>llm_errors.json]
    ErrorLogger --> LogDiagnosis[診断記録<br/>llm_diagnosis_report.json]
    
    LogDetail --> RetryDecision
    LogJSON --> RetryDecision
    LogDiagnosis --> RetryDecision
    
    RetryDecision{リトライ<br/>戦略?}
    
    RetryDecision -->|NO_RETRY| StopTypes{エラータイプ?}
    StopTypes -->|AUTH_ERROR| NoRetryAuth[認証エラー<br/>リトライ不可]
    StopTypes -->|TOKEN_LIMIT| NoRetryToken[トークン制限<br/>リトライ不可]
    StopTypes -->|CONTENT_FILTER| NoRetryContent[コンテンツ<br/>リトライ不可]
    
    RetryDecision -->|RETRY| RetryTypes{エラータイプ?}
    RetryTypes -->|TIMEOUT| TimeoutStrategy[タイムアウト戦略<br/>・最大2回]
    RetryTypes -->|RATE_LIMIT| RateStrategy[レート制限戦略<br/>・指数バックオフ<br/>・最大60秒]
    RetryTypes -->|SERVER_ERROR| ServerStrategy[サーバーエラー戦略<br/>・長め遅延<br/>・最大30秒]
    RetryTypes -->|その他| DefaultStrategy[デフォルト戦略<br/>・基本遅延2秒]
    
    NoRetryAuth --> Fatal
    NoRetryToken --> Fatal
    NoRetryContent --> Fatal
    
    TimeoutStrategy --> ExecuteRetry
    RateStrategy --> ExecuteRetry
    ServerStrategy --> ExecuteRetry
    DefaultStrategy --> ExecuteRetry
    
    ExecuteRetry[リトライ実行]
    ExecuteRetry --> Success{成功?}
    
    Success -->|Yes| RecoverSuccess[正常復帰]
    Success -->|No| CheckAttempts{試行回数<br/>チェック}
    
    CheckAttempts -->|残りあり| ExecuteRetry
    CheckAttempts -->|上限到達| Fatal
    
    Fatal[致命的エラー]
    Fatal --> FatalLog[致命的エラーログ<br/>llm_fatal_error.log<br/>llm_fatal_diagnosis.json]
    
    FatalLog --> DisplaySummary[サマリー表示<br/>・エラー履歴<br/>・診断ファイル一覧]
    
    DisplaySummary --> SystemExit[sys.exit&#40;1&#41;]
    RecoverSuccess --> Continue[処理継続]
    
    style ErrorOccur fill:#ffcdd2
    style LLMError fill:#fff3e0
    style Fatal fill:#ef5350
    style RecoverSuccess fill:#c8e6c9
```