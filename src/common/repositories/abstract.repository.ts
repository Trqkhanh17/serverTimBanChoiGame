import {
  Document,
  FilterQuery,
  Model,
  QueryOptions,
  UpdateQuery,
  Types,
} from 'mongoose';

export abstract class AbstractRepository<T extends Document> {
  constructor(protected readonly model: Model<T>) {}

  async create(createEntityData: unknown): Promise<T> {
    const entity = new this.model(createEntityData);
    return entity.save() as unknown as Promise<T>;
  }

  async findOne(
    filterQuery: FilterQuery<T>,
    projection?: any,
    options?: QueryOptions,
  ): Promise<T | null> {
    return this.model
      .findOne(filterQuery, projection, options)
      .lean<T>(options?.lean ?? true)
      .exec();
  }

  async findOneAndUpdate(
    filterQuery: FilterQuery<T>,
    updateQuery: UpdateQuery<T>,
    options?: QueryOptions,
  ): Promise<T | null> {
    const document = await this.model
      .findOneAndUpdate(filterQuery, updateQuery, {
        new: true,
        ...options,
      })
      .lean<T>(options?.lean ?? true)
      .exec();
    return document;
  }

  async findByIdAndUpdate(
    id: string | Types.ObjectId,
    updateQuery: UpdateQuery<T>,
    options?: QueryOptions,
  ): Promise<T | null> {
    const document = await this.model
      .findByIdAndUpdate(id, updateQuery, {
        new: true,
        ...options,
      })
      .lean<T>(options?.lean ?? true)
      .exec();
    return document;
  }

  async findById(
    id: string | Types.ObjectId,
    projection?: any,
    options?: QueryOptions,
  ): Promise<T | null> {
    return this.model
      .findById(id, projection, options)
      .lean<T>(options?.lean ?? true)
      .exec();
  }

  async find(
    filterQuery: FilterQuery<T>,
    projection?: any,
    options?: QueryOptions,
  ): Promise<T[]> {
    return this.model
      .find(filterQuery, projection, options)
      .lean<T[]>(options?.lean ?? true)
      .exec();
  }

  async exists(filterQuery: FilterQuery<T>): Promise<boolean> {
    const result = await this.model.exists(filterQuery);
    return !!result;
  }

  async countDocuments(filterQuery: FilterQuery<T> = {}): Promise<number> {
    return this.model.countDocuments(filterQuery).exec();
  }

  async updateOne(
    filterQuery: FilterQuery<T>,
    updateQuery: UpdateQuery<T>,
    options?: QueryOptions,
  ) {
    return this.model
      .updateOne(filterQuery, updateQuery, options as any)
      .exec();
  }
}
