namespace java ezbake.data.base.blob.thrift

include "ezbakeBaseTypes.thrift"
include "baseDataService.thrift"
include "ezbakeBaseVisibility.thrift"

struct Blob
{
    1: required string bucket;
    2: required string key;
    3: required binary blob;
    4: required ezbakeBaseVisibility.Visibility visibility;
}

exception BlobException
{
    1: string message
}

service EzBlob extends baseDataService.BaseDataService
{
    void putBlob(1:Blob entry, 2:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);
        
    set<binary> getBlobs(1:string bucketName, 2:string key, 3:ezbakeBaseTypes.EzSecurityToken security) 
        throws (1: BlobException error);
        
    i32 removeBlob(1:string bucketName, 2:string key, 3:ezbakeBaseTypes.EzSecurityToken security) 
        throws (1: BlobException error);

    void copyBlob(1:string sourceBucketName, 2:string sourceKey, 3:string destinationBucketName, 4:string destinationKey, 5:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    string createBucket(1:string bucketName, 2:ezbakeBaseVisibility.Visibility visibility, 3:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    void deleteBucket(1:string bucketName, 2:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    bool doesBucketExist(1:string bucketName, 2:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    bool doesBlobExist(1:string bucketName, 2:string key, 3:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    list<ezbakeBaseVisibility.Visibility> getBlobVisibility(1:string bucketName, 2:string key, 3:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    ezbakeBaseVisibility.Visibility getBucketVisibility(1:string bucketName, 2:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    set<string> listBuckets(1:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    list<Blob> listBlobs(1:string bucketName, 2:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    void setBucketVisibility(1:string bucketName, 2:ezbakeBaseVisibility.Visibility visibility, 3:ezbakeBaseTypes.EzSecurityToken security)
        throws (1: BlobException error);

    void setBlobVisibility(1:string bucketName, 2:string key, 3:ezbakeBaseVisibility.Visibility visibility, 4:ezbakeBaseTypes.EzSecurityToken security)
            throws (1: BlobException error);

}