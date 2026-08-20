import type {
  FilterQuery,
  HydratedDocument,
  Model,
  ProjectionType,
  QueryOptions,
  Types,
  UpdateQuery,
} from 'mongoose';

export abstract class BaseRepository<TEntity extends object> {
  constructor(protected readonly model: Model<TEntity>) {}

  async create(data: Partial<TEntity>): Promise<HydratedDocument<TEntity>> {
    return new this.model(data).save();
  }

  findOne(
    filter: FilterQuery<TEntity>,
    projection?: ProjectionType<TEntity>,
    options?: QueryOptions,
  ): Promise<HydratedDocument<TEntity> | null> {
    return this.model.findOne(filter, projection, options).exec();
  }

  findOneAndUpdate(
    filter: FilterQuery<TEntity>,
    update: UpdateQuery<TEntity>,
    options?: QueryOptions,
  ): Promise<HydratedDocument<TEntity> | null> {
    return this.model
      .findOneAndUpdate(filter, update, { new: true, ...options })
      .exec();
  }

  findByIdAndUpdate(
    id: string | Types.ObjectId,
    update: UpdateQuery<TEntity>,
    options?: QueryOptions,
  ): Promise<HydratedDocument<TEntity> | null> {
    return this.model
      .findByIdAndUpdate(id, update, { new: true, ...options })
      .exec();
  }

  findById(
    id: string | Types.ObjectId,
    projection?: ProjectionType<TEntity>,
    options?: QueryOptions,
  ): Promise<HydratedDocument<TEntity> | null> {
    return this.model.findById(id, projection, options).exec();
  }

  find(
    filter: FilterQuery<TEntity>,
    projection?: ProjectionType<TEntity>,
    options?: QueryOptions,
  ): Promise<HydratedDocument<TEntity>[]> {
    return this.model.find(filter, projection, options).exec();
  }

  async exists(filter: FilterQuery<TEntity>): Promise<boolean> {
    return Boolean(await this.model.exists(filter));
  }

  countDocuments(filter: FilterQuery<TEntity> = {}): Promise<number> {
    return this.model.countDocuments(filter).exec();
  }

  updateOne(filter: FilterQuery<TEntity>, update: UpdateQuery<TEntity>) {
    return this.model.updateOne(filter, update).exec();
  }
}
