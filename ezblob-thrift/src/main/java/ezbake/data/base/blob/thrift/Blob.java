/**
 * Autogenerated by Thrift Compiler (0.9.1)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package ezbake.data.base.blob.thrift;

import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.thrift.scheme.IScheme;
import org.apache.thrift.scheme.SchemeFactory;
import org.apache.thrift.scheme.StandardScheme;

import org.apache.thrift.scheme.TupleScheme;
import org.apache.thrift.protocol.TTupleProtocol;
import org.apache.thrift.protocol.TProtocolException;
import org.apache.thrift.EncodingUtils;
import org.apache.thrift.TException;
import org.apache.thrift.async.AsyncMethodCallback;
import org.apache.thrift.server.AbstractNonblockingServer.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.EnumMap;
import java.util.Set;
import java.util.HashSet;
import java.util.EnumSet;
import java.util.Collections;
import java.util.BitSet;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Blob implements org.apache.thrift.TBase<Blob, Blob._Fields>, java.io.Serializable, Cloneable, Comparable<Blob> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("Blob");

  private static final org.apache.thrift.protocol.TField BUCKET_FIELD_DESC = new org.apache.thrift.protocol.TField("bucket", org.apache.thrift.protocol.TType.STRING, (short)1);
  private static final org.apache.thrift.protocol.TField KEY_FIELD_DESC = new org.apache.thrift.protocol.TField("key", org.apache.thrift.protocol.TType.STRING, (short)2);
  private static final org.apache.thrift.protocol.TField BLOB_FIELD_DESC = new org.apache.thrift.protocol.TField("blob", org.apache.thrift.protocol.TType.STRING, (short)3);
  private static final org.apache.thrift.protocol.TField VISIBILITY_FIELD_DESC = new org.apache.thrift.protocol.TField("visibility", org.apache.thrift.protocol.TType.STRUCT, (short)4);

  private static final Map<Class<? extends IScheme>, SchemeFactory> schemes = new HashMap<Class<? extends IScheme>, SchemeFactory>();
  static {
    schemes.put(StandardScheme.class, new BlobStandardSchemeFactory());
    schemes.put(TupleScheme.class, new BlobTupleSchemeFactory());
  }

  public String bucket; // required
  public String key; // required
  public ByteBuffer blob; // required
  public ezbake.base.thrift.Visibility visibility; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    BUCKET((short)1, "bucket"),
    KEY((short)2, "key"),
    BLOB((short)3, "blob"),
    VISIBILITY((short)4, "visibility");

    private static final Map<String, _Fields> byName = new HashMap<String, _Fields>();

    static {
      for (_Fields field : EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        case 1: // BUCKET
          return BUCKET;
        case 2: // KEY
          return KEY;
        case 3: // BLOB
          return BLOB;
        case 4: // VISIBILITY
          return VISIBILITY;
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    public static _Fields findByName(String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final String _fieldName;

    _Fields(short thriftId, String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    public short getThriftFieldId() {
      return _thriftId;
    }

    public String getFieldName() {
      return _fieldName;
    }
  }

  // isset id assignments
  public static final Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.BUCKET, new org.apache.thrift.meta_data.FieldMetaData("bucket", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.KEY, new org.apache.thrift.meta_data.FieldMetaData("key", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.BLOB, new org.apache.thrift.meta_data.FieldMetaData("blob", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING        , true)));
    tmpMap.put(_Fields.VISIBILITY, new org.apache.thrift.meta_data.FieldMetaData("visibility", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, ezbake.base.thrift.Visibility.class)));
    metaDataMap = Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(Blob.class, metaDataMap);
  }

  public Blob() {
  }

  public Blob(
    String bucket,
    String key,
    ByteBuffer blob,
    ezbake.base.thrift.Visibility visibility)
  {
    this();
    this.bucket = bucket;
    this.key = key;
    this.blob = blob;
    this.visibility = visibility;
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public Blob(Blob other) {
    if (other.isSetBucket()) {
      this.bucket = other.bucket;
    }
    if (other.isSetKey()) {
      this.key = other.key;
    }
    if (other.isSetBlob()) {
      this.blob = org.apache.thrift.TBaseHelper.copyBinary(other.blob);
;
    }
    if (other.isSetVisibility()) {
      this.visibility = new ezbake.base.thrift.Visibility(other.visibility);
    }
  }

  public Blob deepCopy() {
    return new Blob(this);
  }

  @Override
  public void clear() {
    this.bucket = null;
    this.key = null;
    this.blob = null;
    this.visibility = null;
  }

  public String getBucket() {
    return this.bucket;
  }

  public Blob setBucket(String bucket) {
    this.bucket = bucket;
    return this;
  }

  public void unsetBucket() {
    this.bucket = null;
  }

  /** Returns true if field bucket is set (has been assigned a value) and false otherwise */
  public boolean isSetBucket() {
    return this.bucket != null;
  }

  public void setBucketIsSet(boolean value) {
    if (!value) {
      this.bucket = null;
    }
  }

  public String getKey() {
    return this.key;
  }

  public Blob setKey(String key) {
    this.key = key;
    return this;
  }

  public void unsetKey() {
    this.key = null;
  }

  /** Returns true if field key is set (has been assigned a value) and false otherwise */
  public boolean isSetKey() {
    return this.key != null;
  }

  public void setKeyIsSet(boolean value) {
    if (!value) {
      this.key = null;
    }
  }

  public byte[] getBlob() {
    setBlob(org.apache.thrift.TBaseHelper.rightSize(blob));
    return blob == null ? null : blob.array();
  }

  public ByteBuffer bufferForBlob() {
    return blob;
  }

  public Blob setBlob(byte[] blob) {
    setBlob(blob == null ? (ByteBuffer)null : ByteBuffer.wrap(blob));
    return this;
  }

  public Blob setBlob(ByteBuffer blob) {
    this.blob = blob;
    return this;
  }

  public void unsetBlob() {
    this.blob = null;
  }

  /** Returns true if field blob is set (has been assigned a value) and false otherwise */
  public boolean isSetBlob() {
    return this.blob != null;
  }

  public void setBlobIsSet(boolean value) {
    if (!value) {
      this.blob = null;
    }
  }

  public ezbake.base.thrift.Visibility getVisibility() {
    return this.visibility;
  }

  public Blob setVisibility(ezbake.base.thrift.Visibility visibility) {
    this.visibility = visibility;
    return this;
  }

  public void unsetVisibility() {
    this.visibility = null;
  }

  /** Returns true if field visibility is set (has been assigned a value) and false otherwise */
  public boolean isSetVisibility() {
    return this.visibility != null;
  }

  public void setVisibilityIsSet(boolean value) {
    if (!value) {
      this.visibility = null;
    }
  }

  public void setFieldValue(_Fields field, Object value) {
    switch (field) {
    case BUCKET:
      if (value == null) {
        unsetBucket();
      } else {
        setBucket((String)value);
      }
      break;

    case KEY:
      if (value == null) {
        unsetKey();
      } else {
        setKey((String)value);
      }
      break;

    case BLOB:
      if (value == null) {
        unsetBlob();
      } else {
        setBlob((ByteBuffer)value);
      }
      break;

    case VISIBILITY:
      if (value == null) {
        unsetVisibility();
      } else {
        setVisibility((ezbake.base.thrift.Visibility)value);
      }
      break;

    }
  }

  public Object getFieldValue(_Fields field) {
    switch (field) {
    case BUCKET:
      return getBucket();

    case KEY:
      return getKey();

    case BLOB:
      return getBlob();

    case VISIBILITY:
      return getVisibility();

    }
    throw new IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new IllegalArgumentException();
    }

    switch (field) {
    case BUCKET:
      return isSetBucket();
    case KEY:
      return isSetKey();
    case BLOB:
      return isSetBlob();
    case VISIBILITY:
      return isSetVisibility();
    }
    throw new IllegalStateException();
  }

  @Override
  public boolean equals(Object that) {
    if (that == null)
      return false;
    if (that instanceof Blob)
      return this.equals((Blob)that);
    return false;
  }

  public boolean equals(Blob that) {
    if (that == null)
      return false;

    boolean this_present_bucket = true && this.isSetBucket();
    boolean that_present_bucket = true && that.isSetBucket();
    if (this_present_bucket || that_present_bucket) {
      if (!(this_present_bucket && that_present_bucket))
        return false;
      if (!this.bucket.equals(that.bucket))
        return false;
    }

    boolean this_present_key = true && this.isSetKey();
    boolean that_present_key = true && that.isSetKey();
    if (this_present_key || that_present_key) {
      if (!(this_present_key && that_present_key))
        return false;
      if (!this.key.equals(that.key))
        return false;
    }

    boolean this_present_blob = true && this.isSetBlob();
    boolean that_present_blob = true && that.isSetBlob();
    if (this_present_blob || that_present_blob) {
      if (!(this_present_blob && that_present_blob))
        return false;
      if (!this.blob.equals(that.blob))
        return false;
    }

    boolean this_present_visibility = true && this.isSetVisibility();
    boolean that_present_visibility = true && that.isSetVisibility();
    if (this_present_visibility || that_present_visibility) {
      if (!(this_present_visibility && that_present_visibility))
        return false;
      if (!this.visibility.equals(that.visibility))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    HashCodeBuilder builder = new HashCodeBuilder();

    boolean present_bucket = true && (isSetBucket());
    builder.append(present_bucket);
    if (present_bucket)
      builder.append(bucket);

    boolean present_key = true && (isSetKey());
    builder.append(present_key);
    if (present_key)
      builder.append(key);

    boolean present_blob = true && (isSetBlob());
    builder.append(present_blob);
    if (present_blob)
      builder.append(blob);

    boolean present_visibility = true && (isSetVisibility());
    builder.append(present_visibility);
    if (present_visibility)
      builder.append(visibility);

    return builder.toHashCode();
  }

  @Override
  public int compareTo(Blob other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = Boolean.valueOf(isSetBucket()).compareTo(other.isSetBucket());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetBucket()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.bucket, other.bucket);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetKey()).compareTo(other.isSetKey());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetKey()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.key, other.key);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetBlob()).compareTo(other.isSetBlob());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetBlob()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.blob, other.blob);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetVisibility()).compareTo(other.isSetVisibility());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetVisibility()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.visibility, other.visibility);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }

  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  public void read(org.apache.thrift.protocol.TProtocol iprot) throws org.apache.thrift.TException {
    schemes.get(iprot.getScheme()).getScheme().read(iprot, this);
  }

  public void write(org.apache.thrift.protocol.TProtocol oprot) throws org.apache.thrift.TException {
    schemes.get(oprot.getScheme()).getScheme().write(oprot, this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("Blob(");
    boolean first = true;

    sb.append("bucket:");
    if (this.bucket == null) {
      sb.append("null");
    } else {
      sb.append(this.bucket);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("key:");
    if (this.key == null) {
      sb.append("null");
    } else {
      sb.append(this.key);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("blob:");
    if (this.blob == null) {
      sb.append("null");
    } else {
      org.apache.thrift.TBaseHelper.toString(this.blob, sb);
    }
    first = false;
    if (!first) sb.append(", ");
    sb.append("visibility:");
    if (this.visibility == null) {
      sb.append("null");
    } else {
      sb.append(this.visibility);
    }
    first = false;
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    if (bucket == null) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'bucket' was not present! Struct: " + toString());
    }
    if (key == null) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'key' was not present! Struct: " + toString());
    }
    if (blob == null) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'blob' was not present! Struct: " + toString());
    }
    if (visibility == null) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'visibility' was not present! Struct: " + toString());
    }
    // check for sub-struct validity
    if (visibility != null) {
      visibility.validate();
    }
  }

  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    try {
      write(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(out)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, ClassNotFoundException {
    try {
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class BlobStandardSchemeFactory implements SchemeFactory {
    public BlobStandardScheme getScheme() {
      return new BlobStandardScheme();
    }
  }

  private static class BlobStandardScheme extends StandardScheme<Blob> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, Blob struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // BUCKET
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.bucket = iprot.readString();
              struct.setBucketIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // KEY
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.key = iprot.readString();
              struct.setKeyIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 3: // BLOB
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.blob = iprot.readBinary();
              struct.setBlobIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 4: // VISIBILITY
            if (schemeField.type == org.apache.thrift.protocol.TType.STRUCT) {
              struct.visibility = new ezbake.base.thrift.Visibility();
              struct.visibility.read(iprot);
              struct.setVisibilityIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          default:
            org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
        }
        iprot.readFieldEnd();
      }
      iprot.readStructEnd();

      // check for required fields of primitive type, which can't be checked in the validate method
      struct.validate();
    }

    public void write(org.apache.thrift.protocol.TProtocol oprot, Blob struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.bucket != null) {
        oprot.writeFieldBegin(BUCKET_FIELD_DESC);
        oprot.writeString(struct.bucket);
        oprot.writeFieldEnd();
      }
      if (struct.key != null) {
        oprot.writeFieldBegin(KEY_FIELD_DESC);
        oprot.writeString(struct.key);
        oprot.writeFieldEnd();
      }
      if (struct.blob != null) {
        oprot.writeFieldBegin(BLOB_FIELD_DESC);
        oprot.writeBinary(struct.blob);
        oprot.writeFieldEnd();
      }
      if (struct.visibility != null) {
        oprot.writeFieldBegin(VISIBILITY_FIELD_DESC);
        struct.visibility.write(oprot);
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class BlobTupleSchemeFactory implements SchemeFactory {
    public BlobTupleScheme getScheme() {
      return new BlobTupleScheme();
    }
  }

  private static class BlobTupleScheme extends TupleScheme<Blob> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, Blob struct) throws org.apache.thrift.TException {
      TTupleProtocol oprot = (TTupleProtocol) prot;
      oprot.writeString(struct.bucket);
      oprot.writeString(struct.key);
      oprot.writeBinary(struct.blob);
      struct.visibility.write(oprot);
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, Blob struct) throws org.apache.thrift.TException {
      TTupleProtocol iprot = (TTupleProtocol) prot;
      struct.bucket = iprot.readString();
      struct.setBucketIsSet(true);
      struct.key = iprot.readString();
      struct.setKeyIsSet(true);
      struct.blob = iprot.readBinary();
      struct.setBlobIsSet(true);
      struct.visibility = new ezbake.base.thrift.Visibility();
      struct.visibility.read(iprot);
      struct.setVisibilityIsSet(true);
    }
  }

}

