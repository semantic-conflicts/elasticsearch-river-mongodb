package org.elasticsearch.river.mongodb;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.bson.BasicBSONObject;
import org.bson.types.BSONTimestamp;
import org.bson.types.Binary;
import org.elasticsearch.common.Preconditions;
import org.elasticsearch.common.collect.Maps;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.xcontent.support.XContentMapValues;
import org.elasticsearch.river.RiverSettings;
import org.elasticsearch.script.ExecutableScript;
import org.elasticsearch.script.ScriptService;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import com.mongodb.MongoClientOptions;
import com.mongodb.ReadPreference;
import com.mongodb.ServerAddress;
import com.mongodb.util.JSON;
public class MongoDBRiverDefinition {
  public static ESLogger logger=Loggers.getLogger(MongoDBRiverDefinition.class);
  public static String DEFAULT_DB_HOST="localhost";
  public static int DEFAULT_DB_PORT=27017;
  public static int DEFAULT_CONCURRENT_REQUESTS=Runtime.getRuntime().availableProcessors();
  public static int DEFAULT_BULK_ACTIONS=1000;
  public static TimeValue DEFAULT_FLUSH_INTERVAL=TimeValue.timeValueMillis(10);
  public static ByteSizeValue DEFAULT_BULK_SIZE=new ByteSizeValue(5,ByteSizeUnit.MB);
  public static int DEFAULT_CONNECT_TIMEOUT=30000;
  public static int DEFAULT_SOCKET_TIMEOUT=60000;
  public static String DB_FIELD="db";
  public static String SERVERS_FIELD="servers";
  public static String HOST_FIELD="host";
  public static String PORT_FIELD="port";
  public static String OPTIONS_FIELD="options";
  public static String SECONDARY_READ_PREFERENCE_FIELD="secondary_read_preference";
  public static String CONNECT_TIMEOUT="connect_timeout";
  public static String SOCKET_TIMEOUT="socket_timeout";
  public static String SSL_CONNECTION_FIELD="ssl";
  public static String SSL_VERIFY_CERT_FIELD="ssl_verify_certificate";
  public static String IS_MONGOS_FIELD="is_mongos";
  public static String DROP_COLLECTION_FIELD="drop_collection";
  public static String EXCLUDE_FIELDS_FIELD="exclude_fields";
  public static String INCLUDE_FIELDS_FIELD="include_fields";
  public static String INCLUDE_COLLECTION_FIELD="include_collection";
  public static String INITIAL_TIMESTAMP_FIELD="initial_timestamp";
  public static String INITIAL_TIMESTAMP_SCRIPT_TYPE_FIELD="script_type";
  public static String INITIAL_TIMESTAMP_SCRIPT_FIELD="script";
  public static String ADVANCED_TRANSFORMATION_FIELD="advanced_transformation";
  public static String SKIP_INITIAL_IMPORT_FIELD="skip_initial_import";
  public static String PARENT_TYPES_FIELD="parent_types";
  public static String STORE_STATISTICS_FIELD="store_statistics";
  public static String IMPORT_ALL_COLLECTIONS_FIELD="import_all_collections";
  public static String DISABLE_INDEX_REFRESH_FIELD="disable_index_refresh";
  public static String FILTER_FIELD="filter";
  public static String CREDENTIALS_FIELD="credentials";
  public static String USER_FIELD="user";
  public static String PASSWORD_FIELD="password";
  public static String SCRIPT_FIELD="script";
  public static String SCRIPT_TYPE_FIELD="script_type";
  public static String COLLECTION_FIELD="collection";
  public static String GRIDFS_FIELD="gridfs";
  public static String INDEX_OBJECT="index";
  public static String NAME_FIELD="name";
  public static String TYPE_FIELD="type";
  public static String LOCAL_DB_FIELD="local";
  public static String ADMIN_DB_FIELD="admin";
  public static String THROTTLE_SIZE_FIELD="throttle_size";
  public static String BULK_SIZE_FIELD="bulk_size";
  public static String BULK_TIMEOUT_FIELD="bulk_timeout";
  public static String CONCURRENT_BULK_REQUESTS_FIELD="concurrent_bulk_requests";
  public static String BULK_FIELD="bulk";
  public static String ACTIONS_FIELD="actions";
  public static String SIZE_FIELD="size";
  public static String CONCURRENT_REQUESTS_FIELD="concurrent_requests";
  public static String FLUSH_INTERVAL_FIELD="flush_interval";
  public String riverName;
  public String riverIndexName;
  public List<ServerAddress> mongoServers=new ArrayList<ServerAddress>();
  public String mongoDb;
  public String mongoCollection;
  public boolean mongoGridFS;
  public BasicDBObject mongoOplogFilter;
  public BasicDBObject mongoCollectionFilter;
  public String mongoAdminUser;
  public String mongoAdminPassword;
  public String mongoLocalUser;
  public String mongoLocalPassword;
  public MongoClientOptions mongoClientOptions;
  public int connectTimeout;
  public int socketTimeout;
  public boolean mongoSecondaryReadPreference;
  public boolean mongoUseSSL;
  public boolean mongoSSLVerifyCertificate;
  public boolean dropCollection;
  public Boolean isMongos;
  public Set<String> excludeFields;
  public Set<String> includeFields;
  public String includeCollection;
  public Timestamp<?> initialTimestamp;
  public String script;
  public String scriptType;
  public boolean advancedTransformation;
  public boolean skipInitialImport;
  public Set<String> parentTypes;
  public boolean storeStatistics;
  public String statisticsIndexName;
  public String statisticsTypeName;
  public boolean importAllCollections;
  public boolean disableIndexRefresh;
  public String indexName;
  public String typeName;
  public int throttleSize;
  public Bulk bulk;
public static class Builder {
    public String riverName;
    public String riverIndexName;
    public List<ServerAddress> mongoServers=new ArrayList<ServerAddress>();
    public String mongoDb;
    public String mongoCollection;
    public boolean mongoGridFS;
    public BasicDBObject mongoOplogFilter;
    public BasicDBObject mongoCollectionFilter=new BasicDBObject();
    public String mongoAdminUser="";
    public String mongoAdminPassword="";
    public String mongoLocalUser="";
    public String mongoLocalPassword="";
    public MongoClientOptions mongoClientOptions=null;
    public int connectTimeout=0;
    public int socketTimeout=0;
    public boolean mongoSecondaryReadPreference=false;
    public boolean mongoUseSSL=false;
    public boolean mongoSSLVerifyCertificate=false;
    public boolean dropCollection=false;
    public Boolean isMongos=null;
    public Set<String> excludeFields=null;
    public Set<String> includeFields=null;
    public String includeCollection="";
    public Timestamp<?> initialTimestamp=null;
    public String script=null;
    public String scriptType=null;
    public boolean advancedTransformation=false;
    public boolean skipInitialImport;
    public Set<String> parentTypes=null;
    public boolean storeStatistics;
    public String statisticsIndexName;
    public String statisticsTypeName;
    public boolean importAllCollections;
    public boolean disableIndexRefresh;
    public String indexName;
    public String typeName;
    public int throttleSize;
    public Bulk bulk;
    public Builder mongoServers(    List<ServerAddress> mongoServers){
      this.mongoServers=mongoServers;
      return this;
    }
    public Builder riverName(    String riverName){
      this.riverName=riverName;
      return this;
    }
    public Builder riverIndexName(    String riverIndexName){
      this.riverIndexName=riverIndexName;
      return this;
    }
    public Builder mongoDb(    String mongoDb){
      this.mongoDb=mongoDb;
      return this;
    }
    public Builder mongoCollection(    String mongoCollection){
      this.mongoCollection=mongoCollection;
      return this;
    }
    public Builder mongoGridFS(    boolean mongoGridFS){
      this.mongoGridFS=mongoGridFS;
      return this;
    }
    public Builder mongoOplogFilter(    BasicDBObject mongoOplogFilter){
      this.mongoOplogFilter=mongoOplogFilter;
      return this;
    }
    public Builder mongoCollectionFilter(    BasicDBObject mongoCollectionFilter){
      this.mongoCollectionFilter=mongoCollectionFilter;
      return this;
    }
    public Builder mongoAdminUser(    String mongoAdminUser){
      this.mongoAdminUser=mongoAdminUser;
      return this;
    }
    public Builder mongoAdminPassword(    String mongoAdminPassword){
      this.mongoAdminPassword=mongoAdminPassword;
      return this;
    }
    public Builder mongoLocalUser(    String mongoLocalUser){
      this.mongoLocalUser=mongoLocalUser;
      return this;
    }
    public Builder mongoLocalPassword(    String mongoLocalPassword){
      this.mongoLocalPassword=mongoLocalPassword;
      return this;
    }
    public Builder mongoClientOptions(    MongoClientOptions mongoClientOptions){
      this.mongoClientOptions=mongoClientOptions;
      return this;
    }
    public Builder connectTimeout(    int connectTimeout){
      this.connectTimeout=connectTimeout;
      return this;
    }
    public Builder socketTimeout(    int socketTimeout){
      this.socketTimeout=socketTimeout;
      return this;
    }
    public Builder mongoSecondaryReadPreference(    boolean mongoSecondaryReadPreference){
      this.mongoSecondaryReadPreference=mongoSecondaryReadPreference;
      return this;
    }
    public Builder mongoUseSSL(    boolean mongoUseSSL){
      this.mongoUseSSL=mongoUseSSL;
      return this;
    }
    public Builder mongoSSLVerifyCertificate(    boolean mongoSSLVerifyCertificate){
      this.mongoSSLVerifyCertificate=mongoSSLVerifyCertificate;
      return this;
    }
    public Builder dropCollection(    boolean dropCollection){
      this.dropCollection=dropCollection;
      return this;
    }
    public Builder isMongos(    Boolean isMongos){
      this.isMongos=isMongos;
      return this;
    }
    public Builder excludeFields(    Set<String> excludeFields){
      this.excludeFields=excludeFields;
      return this;
    }
    public Builder includeFields(    Set<String> includeFields){
      this.includeFields=includeFields;
      return this;
    }
    public Builder includeCollection(    String includeCollection){
      this.includeCollection=includeCollection;
      return this;
    }
    public Builder disableIndexRefresh(    boolean disableIndexRefresh){
      this.disableIndexRefresh=disableIndexRefresh;
      return this;
    }
    public Builder initialTimestamp(    Binary initialTimestamp){
      this.initialTimestamp=new Timestamp.GTID(initialTimestamp.getData(),null);
      return this;
    }
    public Builder initialTimestamp(    BSONTimestamp initialTimestamp){
      this.initialTimestamp=new Timestamp.BSON(initialTimestamp);
      return this;
    }
    public Builder advancedTransformation(    boolean advancedTransformation){
      this.advancedTransformation=advancedTransformation;
      return this;
    }
    public Builder skipInitialImport(    boolean skipInitialImport){
      this.skipInitialImport=skipInitialImport;
      return this;
    }
    public Builder parentTypes(    Set<String> parentTypes){
      this.parentTypes=parentTypes;
      return this;
    }
    public Builder storeStatistics(    boolean storeStatistics){
      this.storeStatistics=storeStatistics;
      return this;
    }
    public Builder statisticsIndexName(    String statisticsIndexName){
      this.statisticsIndexName=statisticsIndexName;
      return this;
    }
    public Builder statisticsTypeName(    String statisticsTypeName){
      this.statisticsTypeName=statisticsTypeName;
      return this;
    }
    public Builder importAllCollections(    boolean importAllCollections){
      this.importAllCollections=importAllCollections;
      return this;
    }
    public Builder script(    String script){
      this.script=script;
      return this;
    }
    public Builder scriptType(    String scriptType){
      this.scriptType=scriptType;
      return this;
    }
    public Builder indexName(    String indexName){
      this.indexName=indexName;
      return this;
    }
    public Builder typeName(    String typeName){
      this.typeName=typeName;
      return this;
    }
    public Builder throttleSize(    int throttleSize){
      this.throttleSize=throttleSize;
      return this;
    }
    public Builder bulk(    Bulk bulk){
      this.bulk=bulk;
      return this;
    }
    public MongoDBRiverDefinition build(){
      return new MongoDBRiverDefinition(this);
    }
    public Builder(){
    }
  }
static class Bulk {
    public int concurrentRequests;
    public int bulkActions;
    public ByteSizeValue bulkSize;
    public TimeValue flushInterval;
static class Builder {
      public int concurrentRequests=DEFAULT_CONCURRENT_REQUESTS;
      public int bulkActions=DEFAULT_BULK_ACTIONS;
      public ByteSizeValue bulkSize=DEFAULT_BULK_SIZE;
      public TimeValue flushInterval=DEFAULT_FLUSH_INTERVAL;
      public Builder concurrentRequests(      int concurrentRequests){
        this.concurrentRequests=concurrentRequests;
        return this;
      }
      public Builder bulkActions(      int bulkActions){
        this.bulkActions=bulkActions;
        return this;
      }
      public Builder bulkSize(      ByteSizeValue bulkSize){
        this.bulkSize=bulkSize;
        return this;
      }
      public Builder flushInterval(      TimeValue flushInterval){
        this.flushInterval=flushInterval;
        return this;
      }
      /** 
 * Builds a new bulk processor.
 */
      public Bulk build(){
        return new Bulk(this);
      }
      public Builder(){
      }
    }
    public Bulk(    final Builder builder){
      this.bulkActions=builder.bulkActions;
      this.bulkSize=builder.bulkSize;
      this.concurrentRequests=builder.concurrentRequests;
      this.flushInterval=builder.flushInterval;
    }
    public int getConcurrentRequests(){
      return concurrentRequests;
    }
    public int getBulkActions(){
      return bulkActions;
    }
    public ByteSizeValue getBulkSize(){
      return bulkSize;
    }
    public TimeValue getFlushInterval(){
      return flushInterval;
    }
    public Bulk(){
    }
  }
  @SuppressWarnings("unchecked") public synchronized static MongoDBRiverDefinition parseSettings(  String riverName,  String riverIndexName,  RiverSettings settings,  ScriptService scriptService){
    logger.info("Parse river settings for {}",riverName);
    Preconditions.checkNotNull(riverName,"No riverName specified");
    Preconditions.checkNotNull(riverIndexName,"No riverIndexName specified");
    Preconditions.checkNotNull(settings,"No settings specified");
    Builder builder=new Builder();
    builder.riverName(riverName);
    builder.riverIndexName(riverIndexName);
    List<ServerAddress> mongoServers=new ArrayList<ServerAddress>();
    String mongoHost;
    int mongoPort;
    if (settings.settings().containsKey(MongoDBRiver.TYPE)) {
      Map<String,Object> mongoSettings=(Map<String,Object>)settings.settings().get(MongoDBRiver.TYPE);
      if (mongoSettings.containsKey(SERVERS_FIELD)) {
        Object mongoServersSettings=mongoSettings.get(SERVERS_FIELD);
        logger.trace("mongoServersSettings: " + mongoServersSettings);
        boolean array=XContentMapValues.isArray(mongoServersSettings);
        if (array) {
          ArrayList<Map<String,Object>> feeds=(ArrayList<Map<String,Object>>)mongoServersSettings;
          for (          Map<String,Object> feed : feeds) {
            mongoHost=XContentMapValues.nodeStringValue(feed.get(HOST_FIELD),null);
            mongoPort=XContentMapValues.nodeIntegerValue(feed.get(PORT_FIELD),DEFAULT_DB_PORT);
            logger.info("Server: " + mongoHost + " - "+ mongoPort);
            try {
              mongoServers.add(new ServerAddress(mongoHost,mongoPort));
            }
 catch (            UnknownHostException uhEx) {
              logger.warn("Cannot add mongo server {}:{}",uhEx,mongoHost,mongoPort);
            }
          }
        }
      }
 else {
        mongoHost=XContentMapValues.nodeStringValue(mongoSettings.get(HOST_FIELD),DEFAULT_DB_HOST);
        mongoPort=XContentMapValues.nodeIntegerValue(mongoSettings.get(PORT_FIELD),DEFAULT_DB_PORT);
        try {
          mongoServers.add(new ServerAddress(mongoHost,mongoPort));
        }
 catch (        UnknownHostException uhEx) {
          logger.warn("Cannot add mongo server {}:{}",uhEx,mongoHost,mongoPort);
        }
      }
      builder.mongoServers(mongoServers);
      MongoClientOptions.Builder mongoClientOptionsBuilder=MongoClientOptions.builder().socketKeepAlive(true);
      if (mongoSettings.containsKey(OPTIONS_FIELD)) {
        Map<String,Object> mongoOptionsSettings=(Map<String,Object>)mongoSettings.get(OPTIONS_FIELD);
        logger.trace("mongoOptionsSettings: " + mongoOptionsSettings);
        builder.mongoSecondaryReadPreference(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(SECONDARY_READ_PREFERENCE_FIELD),false));
        builder.connectTimeout(XContentMapValues.nodeIntegerValue(mongoOptionsSettings.get(CONNECT_TIMEOUT),DEFAULT_CONNECT_TIMEOUT));
        builder.socketTimeout(XContentMapValues.nodeIntegerValue(mongoOptionsSettings.get(SOCKET_TIMEOUT),DEFAULT_SOCKET_TIMEOUT));
        builder.dropCollection(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(DROP_COLLECTION_FIELD),false));
        String isMongos=XContentMapValues.nodeStringValue(mongoOptionsSettings.get(IS_MONGOS_FIELD),null);
        if (isMongos != null) {
          builder.isMongos(Boolean.valueOf(isMongos));
        }
        builder.mongoUseSSL(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(SSL_CONNECTION_FIELD),false));
        builder.mongoSSLVerifyCertificate(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(SSL_VERIFY_CERT_FIELD),true));
        builder.advancedTransformation(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(ADVANCED_TRANSFORMATION_FIELD),false));
        builder.skipInitialImport(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(SKIP_INITIAL_IMPORT_FIELD),false));
        mongoClientOptionsBuilder.connectTimeout(builder.connectTimeout).socketTimeout(builder.socketTimeout);
        if (builder.mongoSecondaryReadPreference) {
          mongoClientOptionsBuilder.readPreference(ReadPreference.secondaryPreferred());
        }
        if (builder.mongoUseSSL) {
          mongoClientOptionsBuilder.socketFactory(getSSLSocketFactory());
        }
        if (mongoOptionsSettings.containsKey(PARENT_TYPES_FIELD)) {
          Set<String> parentTypes=new HashSet<String>();
          Object parentTypesSettings=mongoOptionsSettings.get(PARENT_TYPES_FIELD);
          logger.debug("parentTypesSettings: " + parentTypesSettings);
          boolean array=XContentMapValues.isArray(parentTypesSettings);
          if (array) {
            ArrayList<String> fields=(ArrayList<String>)parentTypesSettings;
            for (            String field : fields) {
              logger.debug("Field: " + field);
              parentTypes.add(field);
            }
          }
          builder.parentTypes(parentTypes);
        }
        if (mongoOptionsSettings.containsKey(STORE_STATISTICS_FIELD)) {
          Object storeStatistics=mongoOptionsSettings.get(STORE_STATISTICS_FIELD);
          boolean object=XContentMapValues.isObject(storeStatistics);
          if (object) {
            Map<String,Object> storeStatisticsSettings=(Map<String,Object>)storeStatistics;
            builder.storeStatistics(true);
            builder.statisticsIndexName(XContentMapValues.nodeStringValue(storeStatisticsSettings.get(INDEX_OBJECT),riverName + "-stats"));
            builder.statisticsTypeName(XContentMapValues.nodeStringValue(storeStatisticsSettings.get(TYPE_FIELD),"stats"));
          }
 else {
            builder.storeStatistics(XContentMapValues.nodeBooleanValue(storeStatistics,false));
            if (builder.storeStatistics) {
              builder.statisticsIndexName(riverName + "-stats");
              builder.statisticsTypeName("stats");
            }
          }
        }
        builder.importAllCollections(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(IMPORT_ALL_COLLECTIONS_FIELD),false));
        builder.disableIndexRefresh(XContentMapValues.nodeBooleanValue(mongoOptionsSettings.get(DISABLE_INDEX_REFRESH_FIELD),false));
        builder.includeCollection(XContentMapValues.nodeStringValue(mongoOptionsSettings.get(INCLUDE_COLLECTION_FIELD),""));
        if (mongoOptionsSettings.containsKey(INCLUDE_FIELDS_FIELD)) {
          Set<String> includeFields=new HashSet<String>();
          Object includeFieldsSettings=mongoOptionsSettings.get(INCLUDE_FIELDS_FIELD);
          logger.debug("includeFieldsSettings: " + includeFieldsSettings);
          boolean array=XContentMapValues.isArray(includeFieldsSettings);
          if (array) {
            ArrayList<String> fields=(ArrayList<String>)includeFieldsSettings;
            for (            String field : fields) {
              logger.debug("Field: " + field);
              includeFields.add(field);
            }
          }
          if (!includeFields.contains(MongoDBRiver.MONGODB_ID_FIELD)) {
            includeFields.add(MongoDBRiver.MONGODB_ID_FIELD);
          }
          builder.includeFields(includeFields);
        }
 else         if (mongoOptionsSettings.containsKey(EXCLUDE_FIELDS_FIELD)) {
          Set<String> excludeFields=new HashSet<String>();
          Object excludeFieldsSettings=mongoOptionsSettings.get(EXCLUDE_FIELDS_FIELD);
          logger.debug("excludeFieldsSettings: " + excludeFieldsSettings);
          boolean array=XContentMapValues.isArray(excludeFieldsSettings);
          if (array) {
            ArrayList<String> fields=(ArrayList<String>)excludeFieldsSettings;
            for (            String field : fields) {
              logger.debug("Field: " + field);
              excludeFields.add(field);
            }
          }
          builder.excludeFields(excludeFields);
        }
        if (mongoOptionsSettings.containsKey(INITIAL_TIMESTAMP_FIELD)) {
          BSONTimestamp timeStamp=null;
          try {
            Map<String,Object> initalTimestampSettings=(Map<String,Object>)mongoOptionsSettings.get(INITIAL_TIMESTAMP_FIELD);
            String scriptType="js";
            if (initalTimestampSettings.containsKey(INITIAL_TIMESTAMP_SCRIPT_TYPE_FIELD)) {
              scriptType=initalTimestampSettings.get(INITIAL_TIMESTAMP_SCRIPT_TYPE_FIELD).toString();
            }
            if (initalTimestampSettings.containsKey(INITIAL_TIMESTAMP_SCRIPT_FIELD)) {
              ExecutableScript scriptExecutable=scriptService.executable(scriptType,initalTimestampSettings.get(INITIAL_TIMESTAMP_SCRIPT_FIELD).toString(),ScriptService.ScriptType.INLINE,Maps.newHashMap());
              Object ctx=scriptExecutable.run();
              logger.trace("initialTimestamp script returned: {}",ctx);
              if (ctx != null) {
                long timestamp=Long.parseLong(ctx.toString());
                timeStamp=new BSONTimestamp((int)(new Date(timestamp).getTime() / 1000),1);
              }
            }
          }
 catch (          Throwable t) {
            logger.warn("Could set initial timestamp",t,new Object());
          }
 finally {
            builder.initialTimestamp(timeStamp);
          }
        }
      }
      builder.mongoClientOptions(mongoClientOptionsBuilder.build());
      if (mongoSettings.containsKey(CREDENTIALS_FIELD)) {
        String dbCredential;
        String mau="";
        String map="";
        String mlu="";
        String mlp="";
        Object mongoCredentialsSettings=mongoSettings.get(CREDENTIALS_FIELD);
        boolean array=XContentMapValues.isArray(mongoCredentialsSettings);
        if (array) {
          ArrayList<Map<String,Object>> credentials=(ArrayList<Map<String,Object>>)mongoCredentialsSettings;
          for (          Map<String,Object> credential : credentials) {
            dbCredential=XContentMapValues.nodeStringValue(credential.get(DB_FIELD),null);
            if (ADMIN_DB_FIELD.equals(dbCredential)) {
              mau=XContentMapValues.nodeStringValue(credential.get(USER_FIELD),null);
              map=XContentMapValues.nodeStringValue(credential.get(PASSWORD_FIELD),null);
            }
 else             if (LOCAL_DB_FIELD.equals(dbCredential)) {
              mlu=XContentMapValues.nodeStringValue(credential.get(USER_FIELD),null);
              mlp=XContentMapValues.nodeStringValue(credential.get(PASSWORD_FIELD),null);
            }
          }
        }
        builder.mongoAdminUser(mau);
        builder.mongoAdminPassword(map);
        builder.mongoLocalUser(mlu);
        builder.mongoLocalPassword(mlp);
      }
      builder.mongoDb(XContentMapValues.nodeStringValue(mongoSettings.get(DB_FIELD),riverName));
      builder.mongoCollection(XContentMapValues.nodeStringValue(mongoSettings.get(COLLECTION_FIELD),riverName));
      builder.mongoGridFS(XContentMapValues.nodeBooleanValue(mongoSettings.get(GRIDFS_FIELD),false));
      if (mongoSettings.containsKey(FILTER_FIELD)) {
        String filter=XContentMapValues.nodeStringValue(mongoSettings.get(FILTER_FIELD),"");
        filter=removePrefix("o.",filter);
        builder.mongoCollectionFilter(convertToBasicDBObject(filter));
        builder.mongoOplogFilter(convertToBasicDBObject(removePrefix("o.",filter)));
      }
      if (mongoSettings.containsKey(SCRIPT_FIELD)) {
        String scriptType="js";
        builder.script(mongoSettings.get(SCRIPT_FIELD).toString());
        if (mongoSettings.containsKey("scriptType")) {
          scriptType=mongoSettings.get("scriptType").toString();
        }
 else         if (mongoSettings.containsKey(SCRIPT_TYPE_FIELD)) {
          scriptType=mongoSettings.get(SCRIPT_TYPE_FIELD).toString();
        }
        builder.scriptType(scriptType);
      }
    }
 else {
      mongoHost=DEFAULT_DB_HOST;
      mongoPort=DEFAULT_DB_PORT;
      try {
        mongoServers.add(new ServerAddress(mongoHost,mongoPort));
        builder.mongoServers(mongoServers);
      }
 catch (      UnknownHostException e) {
        e.printStackTrace();
      }
      builder.mongoDb(riverName);
      builder.mongoCollection(riverName);
    }
    if (settings.settings().containsKey(INDEX_OBJECT)) {
      Map<String,Object> indexSettings=(Map<String,Object>)settings.settings().get(INDEX_OBJECT);
      builder.indexName(XContentMapValues.nodeStringValue(indexSettings.get(NAME_FIELD),builder.mongoDb));
      builder.typeName(XContentMapValues.nodeStringValue(indexSettings.get(TYPE_FIELD),builder.mongoDb));
      Bulk.Builder bulkBuilder=new Bulk.Builder();
      if (indexSettings.containsKey(BULK_FIELD)) {
        Map<String,Object> bulkSettings=(Map<String,Object>)indexSettings.get(BULK_FIELD);
        int bulkActions=XContentMapValues.nodeIntegerValue(bulkSettings.get(ACTIONS_FIELD),DEFAULT_BULK_ACTIONS);
        bulkBuilder.bulkActions(bulkActions);
        String size=XContentMapValues.nodeStringValue(bulkSettings.get(SIZE_FIELD),DEFAULT_BULK_SIZE.toString());
        bulkBuilder.bulkSize(ByteSizeValue.parseBytesSizeValue(size));
        bulkBuilder.concurrentRequests(XContentMapValues.nodeIntegerValue(bulkSettings.get(CONCURRENT_REQUESTS_FIELD),EsExecutors.boundedNumberOfProcessors(ImmutableSettings.EMPTY)));
        bulkBuilder.flushInterval(XContentMapValues.nodeTimeValue(bulkSettings.get(FLUSH_INTERVAL_FIELD),DEFAULT_FLUSH_INTERVAL));
        builder.throttleSize(XContentMapValues.nodeIntegerValue(indexSettings.get(THROTTLE_SIZE_FIELD),bulkActions * 5));
      }
 else {
        int bulkActions=XContentMapValues.nodeIntegerValue(indexSettings.get(BULK_SIZE_FIELD),DEFAULT_BULK_ACTIONS);
        bulkBuilder.bulkActions(bulkActions);
        bulkBuilder.bulkSize(DEFAULT_BULK_SIZE);
        bulkBuilder.flushInterval(XContentMapValues.nodeTimeValue(indexSettings.get(BULK_TIMEOUT_FIELD),DEFAULT_FLUSH_INTERVAL));
        bulkBuilder.concurrentRequests(XContentMapValues.nodeIntegerValue(indexSettings.get(CONCURRENT_BULK_REQUESTS_FIELD),EsExecutors.boundedNumberOfProcessors(ImmutableSettings.EMPTY)));
        builder.throttleSize(XContentMapValues.nodeIntegerValue(indexSettings.get(THROTTLE_SIZE_FIELD),bulkActions * 5));
      }
      builder.bulk(bulkBuilder.build());
    }
 else {
      builder.indexName(builder.mongoDb);
      builder.typeName(builder.mongoDb);
      builder.bulk(new Bulk.Builder().build());
    }
    return builder.build();
  }
  public static SocketFactory getSSLSocketFactory(){
    SocketFactory sslSocketFactory;
    try {
      final TrustManager[] trustAllCerts=new TrustManager[]{new X509TrustManager(){
        @Override public X509Certificate[] getAcceptedIssuers(){
          return null;
        }
        @Override public void checkServerTrusted(        X509Certificate[] chain,        String authType) throws CertificateException {
        }
        @Override public void checkClientTrusted(        X509Certificate[] chain,        String authType) throws CertificateException {
        }
      }
};
      final SSLContext sslContext=SSLContext.getInstance("SSL");
      sslContext.init(null,trustAllCerts,new java.security.SecureRandom());
      sslSocketFactory=sslContext.getSocketFactory();
      return sslSocketFactory;
    }
 catch (    Exception ex) {
      logger.error("Unable to build ssl socket factory without certificate validation, using default instead.",ex);
    }
    return SSLSocketFactory.getDefault();
  }
  public static BasicDBObject convertToBasicDBObject(  String object){
    if (object == null || object.length() == 0) {
      return new BasicDBObject();
    }
 else {
      return (BasicDBObject)JSON.parse(object);
    }
  }
  public static String removePrefix(  String prefix,  String object){
    return addRemovePrefix(prefix,object,false);
  }
  public static String addPrefix(  String prefix,  String object){
    return addRemovePrefix(prefix,object,true);
  }
  public static String addRemovePrefix(  String prefix,  String object,  boolean add){
    if (prefix == null) {
      throw new IllegalArgumentException("prefix");
    }
    if (object == null) {
      throw new NullPointerException("object");
    }
    if (object.length() == 0) {
      return "";
    }
    DBObject bsonObject=(DBObject)JSON.parse(object);
    BasicBSONObject newObject=new BasicBSONObject();
    for (    String key : bsonObject.keySet()) {
      if (add) {
        newObject.put(prefix + key,bsonObject.get(key));
      }
 else {
        if (key.startsWith(prefix)) {
          newObject.put(key.substring(prefix.length()),bsonObject.get(key));
        }
 else {
          newObject.put(key,bsonObject.get(key));
        }
      }
    }
    return newObject.toString();
  }
  public MongoDBRiverDefinition(  final Builder builder){
    this.riverName=builder.riverName;
    this.riverIndexName=builder.riverIndexName;
    this.mongoServers.addAll(builder.mongoServers);
    this.mongoDb=builder.mongoDb;
    this.mongoCollection=builder.mongoCollection;
    this.mongoGridFS=builder.mongoGridFS;
    this.mongoOplogFilter=builder.mongoOplogFilter;
    this.mongoCollectionFilter=builder.mongoCollectionFilter;
    this.mongoAdminUser=builder.mongoAdminUser;
    this.mongoAdminPassword=builder.mongoAdminPassword;
    this.mongoLocalUser=builder.mongoLocalUser;
    this.mongoLocalPassword=builder.mongoLocalPassword;
    this.mongoClientOptions=builder.mongoClientOptions;
    this.connectTimeout=builder.connectTimeout;
    this.socketTimeout=builder.socketTimeout;
    this.mongoSecondaryReadPreference=builder.mongoSecondaryReadPreference;
    this.mongoUseSSL=builder.mongoUseSSL;
    this.mongoSSLVerifyCertificate=builder.mongoSSLVerifyCertificate;
    this.dropCollection=builder.dropCollection;
    this.isMongos=builder.isMongos;
    this.excludeFields=builder.excludeFields;
    this.includeFields=builder.includeFields;
    this.includeCollection=builder.includeCollection;
    this.initialTimestamp=builder.initialTimestamp;
    this.script=builder.script;
    this.scriptType=builder.scriptType;
    this.advancedTransformation=builder.advancedTransformation;
    this.skipInitialImport=builder.skipInitialImport;
    this.parentTypes=builder.parentTypes;
    this.storeStatistics=builder.storeStatistics;
    this.statisticsIndexName=builder.statisticsIndexName;
    this.statisticsTypeName=builder.statisticsTypeName;
    this.importAllCollections=builder.importAllCollections;
    this.disableIndexRefresh=builder.disableIndexRefresh;
    this.indexName=builder.indexName;
    this.typeName=builder.typeName;
    this.throttleSize=builder.throttleSize;
    this.bulk=builder.bulk;
  }
  public List<ServerAddress> getMongoServers(){
    return mongoServers;
  }
  public String getRiverName(){
    return riverName;
  }
  public String getRiverIndexName(){
    return riverIndexName;
  }
  public String getMongoDb(){
    return mongoDb;
  }
  public String getMongoCollection(){
    return mongoCollection;
  }
  public boolean isMongoGridFS(){
    return mongoGridFS;
  }
  public BasicDBObject getMongoOplogFilter(){
    return mongoOplogFilter;
  }
  public BasicDBObject getMongoCollectionFilter(){
    return mongoCollectionFilter;
  }
  public String getMongoAdminUser(){
    return mongoAdminUser;
  }
  public String getMongoAdminPassword(){
    return mongoAdminPassword;
  }
  public String getMongoLocalUser(){
    return mongoLocalUser;
  }
  public String getMongoLocalPassword(){
    return mongoLocalPassword;
  }
  public MongoClientOptions getMongoClientOptions(){
    return mongoClientOptions;
  }
  public int getConnectTimeout(){
    return connectTimeout;
  }
  public int getSocketTimeout(){
    return socketTimeout;
  }
  public boolean isMongoSecondaryReadPreference(){
    return mongoSecondaryReadPreference;
  }
  public boolean isMongoUseSSL(){
    return mongoUseSSL;
  }
  public boolean isMongoSSLVerifyCertificate(){
    return mongoSSLVerifyCertificate;
  }
  public boolean isDropCollection(){
    return dropCollection;
  }
  public Boolean isMongos(){
    return isMongos;
  }
  public Set<String> getExcludeFields(){
    return excludeFields;
  }
  public Set<String> getIncludeFields(){
    return includeFields;
  }
  public String getIncludeCollection(){
    return includeCollection;
  }
  public Timestamp<?> getInitialTimestamp(){
    return initialTimestamp;
  }
  public String getScript(){
    return script;
  }
  public String getScriptType(){
    return scriptType;
  }
  public boolean isAdvancedTransformation(){
    return advancedTransformation;
  }
  public boolean isSkipInitialImport(){
    return skipInitialImport;
  }
  public Set<String> getParentTypes(){
    return parentTypes;
  }
  public boolean isStoreStatistics(){
    return storeStatistics;
  }
  public String getStatisticsIndexName(){
    return statisticsIndexName;
  }
  public String getStatisticsTypeName(){
    return statisticsTypeName;
  }
  public boolean isImportAllCollections(){
    return importAllCollections;
  }
  public boolean isDisableIndexRefresh(){
    return disableIndexRefresh;
  }
  public String getIndexName(){
    return indexName;
  }
  public String getTypeName(){
    return typeName;
  }
  public int getThrottleSize(){
    return throttleSize;
  }
  public String getMongoOplogNamespace(){
    return getMongoDb() + "." + getMongoCollection();
  }
  public Bulk getBulk(){
    return bulk;
  }
  public MongoDBRiverDefinition(){
  }
}
