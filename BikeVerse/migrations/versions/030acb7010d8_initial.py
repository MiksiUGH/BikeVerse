"""Initial

Revision ID: 030acb7010d8
Revises: 
Create Date: 2025-07-26 19:41:51.170463

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '030acb7010d8'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('achievements',
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('criteria_type', sa.String(), nullable=True),
    sa.Column('criteria_value', sa.Float(), nullable=True),
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('users',
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(), nullable=False),
    sa.Column('level', sa.Integer(), nullable=True),
    sa.Column('exp', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('last_login', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)

    op.create_table('routes',
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('is_public', sa.Boolean(), nullable=True),
    sa.Column('location', sa.String(length=120), nullable=False),
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.ForeignKeyConstraint(['creator_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_achievements',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('achievement_id', sa.Integer(), nullable=False),
    sa.Column('unlocked_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['achievement_id'], ['achievements.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'achievement_id')
    )
    op.create_table('rides',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('route_id', sa.Integer(), nullable=True),
    sa.Column('start_time', sa.DateTime(), nullable=False),
    sa.Column('end_time', sa.DateTime(), nullable=True),
    sa.Column('distance', sa.Float(), nullable=True),
    sa.Column('max_elevation', sa.Float(), nullable=True),
    sa.Column('gps_track', sa.JSON(), nullable=True),
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.CheckConstraint('end_time IS NULL OR end_time >= start_time', name='check_end_time'),
    sa.ForeignKeyConstraint(['route_id'], ['routes.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('rides', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_rides_user_id'), ['user_id'], unique=False)

    op.create_table('route_points',
    sa.Column('route_id', sa.Integer(), nullable=False),
    sa.Column('order', sa.Integer(), nullable=True),
    sa.Column('latitude', sa.Float(), nullable=False),
    sa.Column('longitude', sa.Float(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=True),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('is_ar', sa.Boolean(), nullable=True),
    sa.Column('ar_content_url', sa.String(), nullable=True),
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.ForeignKeyConstraint(['route_id'], ['routes.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('visited_points',
    sa.Column('ride_id', sa.Integer(), nullable=True),
    sa.Column('point_id', sa.Integer(), nullable=True),
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.ForeignKeyConstraint(['point_id'], ['route_points.id'], ),
    sa.ForeignKeyConstraint(['ride_id'], ['rides.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('visited_points', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_visited_points_point_id'), ['point_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_visited_points_ride_id'), ['ride_id'], unique=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('visited_points', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_visited_points_ride_id'))
        batch_op.drop_index(batch_op.f('ix_visited_points_point_id'))

    op.drop_table('visited_points')
    op.drop_table('route_points')
    with op.batch_alter_table('rides', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_rides_user_id'))

    op.drop_table('rides')
    op.drop_table('user_achievements')
    op.drop_table('routes')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_email'))

    op.drop_table('users')
    op.drop_table('achievements')
    # ### end Alembic commands ###
